import enum
import os
import select
import socket
import sys
import threading
import time
import urllib.parse

class default_config: None

default_config.max_threads = 8192
default_config.port = 7777
default_config.recognised_selectors = ['0', '1', '5', '9', 'g', 'h', 'I', 's']
default_config.request_max_size = 8192
default_config.socket_timeout = 1

# error(message)
# Print error message to stderr
def error(message):
	program_name = os.path.basename(sys.argv[0])
	print('%s: Error: %s' % (program_name, message), file = sys.stderr)

# die(message, status = 1) → (Never returns)
# Print error message to stderr and exit with status code
def die(message, status = 1):
	error(message)
	sys.exit(status)

# A base for Exeptions that are used with one argument and that return a string that incorporates said argument
class OneArgumentException(Exception):
	def __init__(self, argument):
		self.argument = argument
	def __str__(self):
		return self.text % self.argument

class UnreachableException(Exception):
	def __str__(self):
		return 'Declared unreachable'

# unreachable() → (Never returns)
# Used to mark a codepath that should never execute
def unreachable():
	raise UnreachableException

# bind(port, backlog = 1) → [sockets...]
# Binds to all available (TCP) interfaces on specified port and returns the sockets
# backlog controls how many connections allowed to wait handling before system drops new ones
def bind(port, backlog = 1):
	# Based on code in https://docs.python.org/3/library/socket.html
	sockets = []
	for res in socket.getaddrinfo(None, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
		af, socktype, proto, canonname, sa = res

		try:
			s = socket.socket(af, socktype, proto)
		except OSError:
			continue
		# Make IPv6 socket only bind on IPv6 address, otherwise may clash with IPv4 and not get enabled
		if af == socket.AF_INET6:
			try:
				s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
			except OSError:
				pass
		try:
			s.bind(sa)
			s.listen(backlog)
		except OSError:
			s.close()
			continue

		sockets.append(s)

	return sockets


# drop_privileges()
# Drops set[ug]id, die()s if unsuccesful
def drop_privileges():
	try:
		uid = os.getuid()
		gid = os.getgid()
		os.setresgid(gid, gid, gid)
		os.setresuid(uid, uid, uid)
	except:
		die('Unable to drop privileges')

class CommandError(OneArgumentException):
	text = 'Error with command: %s'

class SocketReadError(OneArgumentException):
	text = 'Error reading socket: %s'

class SocketReaderCommands(enum.Enum):
	stop = range(1)

# SocketReader(sock) → <SocketReader instance>
# next(<SocketReader instance>) → byte_of_data
# Wraps a socket and exposes it as per-byte iterator. Does not close the socket when it exits
def SocketReader(sock):
	chunk = b''
	while True:
		for byte in chunk:
			command = yield byte

			if command is not None:
				if command == SocketReaderCommands.stop:
					return
				else:
					raise CommandError('%s not recognised' % repr(command))

		try:
			chunk = sock.recv(1024)
		except socket.timeout:
			raise SocketReadError('Error reading socket: Remote end timed out')

		if not chunk:
			break

# extract_selector_path(selector_path, *, config) → selector, path
# Extract selector and path components from a HTTP path
def extract_selector_path(selector_path, *, config):
	if len(selector_path) > 0 and selector_path[0] == '/':
		selector_path = selector_path[1:]

	if len(selector_path) == 0: # / is by default of type 1
		selector = '1'
		path = selector_path
	elif selector_path[0] in config.recognised_selectors: # Requested path has a selector we recognise, extract it
		selector = selector_path[0]
		path = selector_path[1:]
	else: # We couldn't recognise any selector, return None for it
		selector = None
		path = selector_path

	return selector, path

class PathError(OneArgumentException):
	text = 'Error with request path: %s'

# normalize_path(path, *, config) → normalized_path
# Normalize the path or raise an exception if the path is malformed
def normalize_path(path, *, config):
	path_components = path.split('/')
	normalized_components = []

	for component in path_components:
		if component == '':
			# A dummy left by // or / in beginning or end, ignore
			continue
		elif component == '.':
			# foo/. = foo, ./bar = bar, ignore
			continue
		elif component == '..':
			# foo/bar/.. = foo, drop last component
			# This equality does not always hold in a real unix system. However, there are two reasons these semantics are used
			# 1. Gopher has no concept of symlinks, and many clients have "parent directory" option that drops last component of path
			# 2. This allows for safe usage of symlinks in gopherroot to outside of it, rogue request can't escape to parent directory
			if len(normalized_components) > 0: # Ensure we have a component to drop and drop it
				normalized_components.pop()
			else:
				# Attempted .. on an empty path, means attempting to point outside gopherroot
				raise PathError('Path points outside gopherroot')
		else:
			# A normal path component, add to the normalized path
			normalized_components.append(component)

	return '/'.join(normalized_components)

class RequestError(OneArgumentException):
	text = 'Error with handling request: %s'

class Protocol(enum.Enum):
	gopher, gopherplus, http = range(3)

# get_request(sock, *, config) → path, protocol, rest
# Read request from socket and parse it.
# path is the requested path, protocol is Protocol.gopher or Protocol.http depending on the request protocol
# rest is protocol-dependant information
def get_request(sockreader, *, config):
	protocol = None

	request = bytearray()

	while True:
		try:
			request.append(next(sockreader))
		except StopIteration: # Other end hung up before sending a full header
			raise RequestError('Remote end hung up unexpectedly')

		if len(request) >= config.request_max_size:
			raise RequestError('Request too long')

		# We have enough data to recognise a HTTP request
		if protocol is None and len(request) >= 4:
			# Does it look like a HTTP GET request?
			if request[:3] == bytearray(b'GET') and chr(request[3]) in [' ', '\r', '\t']:
				# Yes, mark HTTP as protocol
				protocol = Protocol.http
			else:
				# No, mark Gopher as protocol
				protocol = Protocol.gopher

		# End of line reached before a HTTP GET request found, mark Gopher as protocol
		if protocol is None and len(request) >= 1 and request[-1:] == bytearray(b'\n'):
			protocol = Protocol.gopher

		# Twice CR+LF, end of HTTP request
		if protocol == Protocol.http and len(request) >= 4 and request[-4:] == bytearray(b'\r\n\r\n'):
			break

		# Twice LF, malcompliant but support anyways
		if protocol == Protocol.http and len(request) >=2 and request[-2:] == bytearray(b'\n\n'):
			break

		# CR+LF, end of Gopher request
		if protocol == Protocol.gopher and len(request) >= 2 and request[-2:] == bytearray(b'\r\n'):
			break

		# LF, malcompliant but support anyways
		if protocol == Protocol.gopher and len(request) >= 1 and request[-1:] == bytearray(b'\n'):
			break

	if protocol == Protocol.http:
		length = len(request)
		# Start after GET
		index = 3
		# Skip witespace
		while index < length and chr(request[index]) in [' ', '\r', '\n', '\t']: index += 1
		# Found the start of the requested path
		path_start = index
		# Skip until next whitespace (end of requested path)
		while index < length and chr(request[index]) not in [' ', '\r', '\n', '\t']: index += 1
		# Found the end of the requested path
		path_end = index

		selector_path = urllib.parse.unquote(request[path_start:path_end].decode('utf-8'))
		selector, path = extract_selector_path(selector_path, config = config)

		rest = selector

	elif protocol == Protocol.gopher:
		rest = None

		length = len(request)
		index = 0
		# Seek until either end of line or a tab (field separator)
		while index < length and chr(request[index]) not in ['\t', '\r', '\n']: index += 1
		# Found the end of the path
		path_end = index

		path = request[:path_end].decode('utf-8')

		# If another field was present, check to see if it marks a Gopher+ request
		if chr(request[index]) == '\t':
			index += 1
			field_start = index
			# Look until end of line
			while index < length and chr(request[index]) not in ['\r', '\n']: index += 1
			field_end = index

			field = request[field_start:field_end].decode('utf-8')
			# We recognise these as signalling a Gopher+ request
			if len(field) >= 1 and field[0] in ['+', '!', '$']:
				# It was Gopher+, let's update protocol value and stash the field into rest
				protocol = Protocol.gopherplus
				rest = field

	else:
		unreachable()

	path = normalize_path(path, config = config)

	return path, protocol, None

# Worker thread implementation
class Serve(threading.Thread):
	def __init__(self, controller, sock, address, config):
		self.controller = controller
		self.sock = sock
		self.address = address
		self.config = config
		threading.Thread.__init__(self)

	def handle_request(self):
		sockreader = SocketReader(self.sock)
		path, protocol, rest = get_request(sockreader, config = self.config)
		answer = str((path, protocol, rest))+'\n'
		self.sock.sendall(answer.encode('utf-8'))

	def run(self):
		global threads_amount, threads_lock

		try:
			self.handle_request()
		except BaseException as err: # Catch and log exceptions instead of letting to crash, as we need to update the worker thread count on abnormal exit as well
			error('Worker thread (%s) died with: %s' % (self.address, err))
		finally:
			self.sock.close()
			self.controller.thread_end()

class Threads_controller:
	def __init__(self):
		self.threads_amount = 0
		self.threads_lock = threading.Lock()

	# .spawn_thread(sock, address, config)
	# Spawn a new thread to serve a connection if possible, do nothing if not
	def spawn_thread(self, sock, address, config):
		# See if we can spawn a new thread. If not, log an error, close the socket and return. If yes, increment the amount of threads running
		with self.threads_lock:
			if self.threads_amount >= config.max_threads:
				error('Could not serve a request from %s, worker thread limit exhausted' % address)
				sock.close()
				return
			else:
				self.threads_amount += 1

		# Spawn a new worker thread
		Serve(self, sock, address, config).start()

	# .thread_end()
	# Called from worker thread to signal it's exiting
	def thread_end(self):
		with self.threads_lock:
			self.threads_amount -= 1

# listen(config) → (Never returns)
# Binds itself to all interfaces on designated port and listens on incoming connections
# Spawns worker threads to handle the connections
def listen(config):
	# Get sockets that we listen to
	listening_sockets = bind(config.port)
	# Drop privileges, we don't need them after this
	drop_privileges()

	# If we got no sockets to listen to, die
	if listening_sockets == []:
		die('Could not bind to port %i' % config.port)

	# Create a poll object for the listening sockets and a fd→socket map
	listening = select.poll()
	sock_by_fd = {}
	for s in listening_sockets:
		listening.register(s, select.POLLIN)
		sock_by_fd[s.fileno()] = s
	del listening_sockets

	# Create a controller object for the worker threads
	threads_controller = Threads_controller()

	while True:
		# Wait for listening sockets to get activity
		events = listening.poll()
		for fd,event in events:
			assert(event == select.POLLIN)
			# Get socket from table established previously
			s = sock_by_fd[fd]
			# Accept and handle the connection
			conn, addr = s.accept()

			# Set timeout for socket
			conn.settimeout(config.socket_timeout)

			threads_controller.spawn_thread(conn, addr[0], config)

if __name__ == '__main__':
	listen(default_config)
