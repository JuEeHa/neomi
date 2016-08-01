import enum
import os
import select
import socket
import sys
import threading
import time

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

class Protocol(enum.Enum):
	gopher, http = range(2)

class RequestError(OneArgumentException):
	text = 'Error with handling request: %s'

# get_request(sock, *, config) → path, protocol, rest
# Read request from socket and parse it.
# path is the requested path, protocol is Protocol.gopher or Protocol.http depending on the request protocol
# rest is protocol-dependant information
def get_request(sock, *, config):
	request = b''
	while True:
		try:
			data = sock.recv(1024)
		except socket.timeout:
			raise RequestError('Remote end timed out')
		if not data: # Other end hung up before sending a header
			raise RequestError('Remote end hung up unexpectedly')
		if len(request) >= config.request_max_size:
			raise RequestError('Request too long')

		request += data

		if b'\n' in data: # First line has been sent, all we care about for now
			break
	
	request = request.decode('utf-8')
	first_line = request.split('\n')[0]
	if first_line[-1] == '\r':
		first_line = first_line[:-1]
	first_line = first_line.split(' ')
	
	if len(first_line) >= 2 and first_line[0] == 'GET':
		selector_path = first_line[1]
		selector, path = extract_selector_path(selector_path, config = config)
		protocol = Protocol.http
		rest = selector
	else:
		if len(first_line) >= 1:
			path = first_line[0]
		else:
			path = ''
		protocol = Protocol.gophrt
		rest = None
	
	path = normalize_path(path, config = config)

	return path, Protocol.gopher, None

# Worker thread implementation
class Serve(threading.Thread):
	def __init__(self, controller, sock, address, config):
		self.controller = controller
		self.sock = sock
		self.address = address
		self.config = config
		threading.Thread.__init__(self)
	
	def handle_request(self):
		path, protocol, rest = get_request(self.sock, config = self.config)
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
