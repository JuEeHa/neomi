import cgi
import configparser
import enum
import ipaddress
import os
import pathlib
import select
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.parse

class default_config: None

default_config.blacklist_file = pathlib.Path(os.environ['HOME']) / 'gopher_blacklist'
default_config.charset = 'utf-8'
default_config.fallback_mimetype = 'application/octet-stream'
default_config.gopher_root = pathlib.Path(os.environ['HOME']) / 'gopher'
default_config.max_threads = 8192
default_config.port = 7070
default_config.recognised_selectors = ['0', '1', '5', '9', 'g', 'h', 'I', 's']
default_config.request_max_size = 8192
default_config.socket_timeout = 1
default_config.hurl_redirect_page = """<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="refresh" content="2; url=__raw_url__"/>
		<title>Redirecting to __escaped_url__</title>
	<head>
	<body>
		<p>Your gopher client doesn't support the hURL specification. If you are not redirected after 2s, click the link.</p>
		<p>Redirecting to <a href="__raw_url__">__escaped_url__</a></p>
	</body>
</html>"""

# error(message)
# Print error message to stderr
def error(message):
	program_name = os.path.basename(sys.argv[0])
	print('%s: %s Error: %s' % (program_name, time.strftime('%Y-%m-%d %H:%M:%S'), message), file = sys.stderr)
	sys.stderr.flush()

# die(message, status = 1) → (Never returns)
# Print error message to stderr and exit with status code
def die(message, status = 1):
	error(message)
	sys.exit(status)

# log(message)
# Print a log message to stdout
def log(message):
	program_name = os.path.basename(sys.argv[0])
	print('%s: %s %s' % (program_name, time.strftime('%Y-%m-%d %H:%M:%S'), message))
	sys.stdout.flush()

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

		# Set SO_REUSEADDR for less painful server restarting
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

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

class ReaderCommands(enum.Enum):
	stop = range(1)

# SocketReader(sock) → <SocketReader instance>
# next(<SocketReader instance>) → byte_of_data
# Wraps a socket and exposes it as per-byte iterator. Does not close the socket when it exits
def SocketReader(sock):
	chunk = b''
	while True:
		for index in range(len(chunk)):
			command = yield chunk[index]

			if command is not None:
				if command == ReaderCommands.stop:
					# Return the rest of data in buffer
					return chunk[index + 1:]
				else:
					raise CommandError('%s not recognised' % repr(command))

		try:
			chunk = sock.recv(1024)
		except socket.timeout:
			raise SocketReadError('Error reading socket: Remote end timed out')

		if not chunk:
			break

# FileReader(file) → <FileReader instance>
# next(<FileReader instance>) → byte_of_data
# Wraps a bytefile object and exposes it as per-byte iterator. Does not close the file when it exits
def FileReader(file):
	chunk = b''
	while True:
		for index in range(len(chunk)):
			command = yield chunk[index]

			if command is not None:
				if command == ReaderCommands.stop:
					# Return the rest of data in buffer
					return chunk[index + 1:]
				else:
					raise CommandError('%s not recognised' % repr(command))

		chunk = file.read(1024)

		if not chunk:
			break

# StringReader(string) → <StringReader instance>
# next(<StringReader instance>) → byte_of_data
# Wraps a unicode string in a inteface like SocketReader or FileReader
def StringReader(string):
	encoded = string.encode('utf-8')
	for index in range(len(encoded)):
		command = yield encoded[index]

		if command is not None:
			if command == ReaderCommands.stop:
				# Return the rest of data
				return encoded[index + 1:]
			else:
				raise CommandError('%s not recognised' % repr(command))

# extract_selector_path(selector_path, *, config) → selector, path
# Extract selector and path components from a HTTP path
def extract_selector_path(selector_path, *, config):
	# URL unquote the path
	selector_path = urllib.parse.unquote(selector_path)

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

# get_request(sock, *, config) → path, protocol, *rest
# Read request from socket and parse it.
# path is the requested path, protocol is Protocol.gopher or Protocol.http depending on the request protocol
# rest is protocol-dependant information
def get_request(sockreader, *, config):
	protocol = None
	just_headers = False

	request = bytearray()

	while True:
		try:
			request.append(next(sockreader))
		except StopIteration: # Other end hung up before sending a full header
			raise RequestError('Remote end hung up unexpectedly')

		if len(request) >= config.request_max_size:
			raise RequestError('Request too long')

		# We have enough data to recognise a HTTP request
		if protocol is None and len(request) >= 5:
			# Does it look like a HTTP GET request?
			if request[:3] == b'GET' and chr(request[3]) in [' ', '\r', '\t']:
				# Yes, mark HTTP as protocol
				protocol = Protocol.http
			# Does it look like a HTTP HEAD request?
			elif request[:4] == b'HEAD' and chr(request[4]) in [' ', '\r', '\t']:
				# Yes, mark HTTP as the protocol and that we'll only return the headers
				protocol = Protocol.http
				just_headers = True
			else:
				# No, mark Gopher as protocol
				protocol = Protocol.gopher

		# End of line reached before a HTTP GET or HEAD request found, mark Gopher as protocol
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
		# Start after GET/HEAD
		index = 4 if just_headers else 3
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

		# Try to extract user agent
		useragent = None
		for line in request.split(b'\n'):
			ua_string = b'user-agent:'
			if len(line) >= len(ua_string) and line.lower()[:len(ua_string)] == ua_string:
				try:
					useragent = line[len(ua_string):].decode('utf-8')
				except UnicodeDecodeError:
					useragent = line[len(ua_string):].decode('latin-1')
				useragent = useragent.strip()

		rest = (selector, just_headers, useragent)

	elif protocol == Protocol.gopher:
		rest = ()

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
				rest = (field,)

	else:
		unreachable()

	return (path, protocol) + rest

infofiles_cached = set()
infofiles_cached_lock = threading.Lock()

# read_infofile(file_path)
# Reads into caches the contents of .filesinfo file at same directory as file_path
def read_infofile(file_path):
	with infofiles_cached_lock:
		if file_path in infofiles_cached:
			return

	infofile = configparser.ConfigParser()

	infofile_path = file_path.parent / '.filesinfo'
	infofile.read(str(infofile_path))

	for file in infofile.sections():
		if 'mimetype' in infofile[file]:
			with mimetype_cache_lock:
				mimetype_cache[file_path.parent / file] = infofile[file]['mimetype']

	with infofiles_cached_lock:
		infofiles_cached.add(file_path)

# TODO: Read from file
extension_mimetypes = {'.txt': 'text/plain', '.text': 'text/plain', '.log': 'text/plain', '.html': 'text/html'}

mimetype_cache = {}
mimetype_cache_lock = threading.Lock()

# get_mimetype(full_path, *, config) → mimetype
# Return the mime type of given file
def get_mimetype(full_path, *, config):
	mimetype = None
	cached = False

	# Look at the information file in the same directory
	read_infofile(full_path)

	# Try looking up from cache
	with mimetype_cache_lock:
		if full_path in mimetype_cache:
			mimetype = mimetype_cache[full_path]
			cached = True

	# See if it's a gophermap
	if mimetype is None:
		if full_path.name == 'gophermap':
			mimetype = 'text/x-gophermap'

	# Try extension
	if mimetype is None:
		extension = full_path.suffix
		if extension in extension_mimetypes:
			mimetype = extension_mimetypes[extension]

	# Nothing worked, use fallback
	if mimetype is None:
		mimetype = config.fallback_mimetype

	# Write into the cache
	if not cached:
		with mimetype_cache_lock:
			mimetype_cache[full_path] = mimetype

	return mimetype

# get_full_path(path, *, config) → full_path
# Figure out full path for the file
def get_full_path(path, *, config):
	full_path = config.gopher_root / path

	# If it's a directory, use the gophermap file in said directory instead
	st = os.stat(str(full_path))
	if stat.S_ISDIR(st.st_mode):
		full_path = full_path / 'gophermap'

	return full_path

class Status:
	ok, notfound, error = range(3)

# is_text_from_mimetype(mimetype) → is_text
# A simple "is this data text" heuristic
def is_text_from_mimetype(mimetype):
	return mimetype.split('/')[0] == 'text'

# send_header(sock, protocol, status, mimetype, *, config)
# Send a header that matches the provided information
def send_header(sock, protocol, status, mimetype, *, config):
	is_text = is_text_from_mimetype(mimetype)

	if protocol == Protocol.http:
		# We translate gophermaps into HTML, so send HTML mimetype
		if mimetype == 'text/x-gophermap':
			content_type = b'Content-type: text/html'
		else:
			content_type = b'Content-type: ' + mimetype.encode('utf-8')

		# Add character set encoding information if we are transmitting text
		if is_text:
			content_type += ('; charset=%s' % config.charset).encode('utf-8')

		if status == Status.ok:
			statusline = b'HTTP/1.1 200 OK'
		elif status == Status.notfound:
			statusline = b'HTTP/1.1 404 Not Found'
		elif status == Status.error:
			statusline = b'HTTP/1.1 500 Internal Server Error'

		header = statusline + b'\r\n' + content_type + b'\r\n\r\n'

	elif protocol == Protocol.gopherplus:
		if status == Status.ok:
			# Gopher has two ways to transmit data of unknown size, text (+-1) and binary (+-2)
			if is_text:
				header = b'+-1\r\n'
			else:
				header = b'+-2\r\n'
		elif status == Status.notfound:
			header = b'--1\r\n'
		elif status == Status.error:
			# Technically -2 means "Try again later", but there is no code for "server blew up"
			header = b'--2\r\n'

	elif protocol == Protocol.gopher:
		# Gopher has no header
		header = b''

	else:
		unreachable()

	sock.sendall(header)

# send_binaryfile(sock, reader, protocol, *, config)
# Send the data in the given reader as binary
def send_binaryfile(sock, reader, protocol, *, config):
	buffer_max = 1024
	buffer = bytearray()
	left = buffer_max

	for byte in reader:
		if left == 0:
			# Flush buffer
			sock.sendall(buffer)
			left = buffer_max

		buffer.append(byte)

	# If there was something left in the buffer, flush it
	if len(buffer) != 0:
		sock.sendall(buffer)

# send_textfile(sock, reader, protocol, *, config)
# Send the data in the given reader, encoded correctly as text file
def send_textfile(sock, reader, protocol, *, config):
	if protocol == Protocol.http:
		# HTTP needs no additional encoding, send as binary
		send_binaryfile(sock, reader, protocol, config = config)

	elif protocol == Protocol.gopher or protocol == Protocol.gopherplus:
		line = bytearray()

		for byte in reader:
			if chr(byte) == '\n':
				# Append \r\n to end of line, send it, and clear
				line.extend(b'\r\n')
				sock.sendall(line)
				line = bytearray()

			elif chr(byte) == '.' and len(line) == 0:
				# . in the beginning of line, needs to be quoted
				line.extend(b'..')

			else:
				# Add to the line
				line.append(byte)

		# If there was no terminating \n, flush the line buffer
		if len(line) != 0:
			line.extend(b'\r\n')
			sock.sendall(line)

		# Signal end of text
		sock.sendall(b'.\r\n')

	else:
		unreachable()

# html_encode(bytestring) -> encoded_bytestring
# Makes bytestring usable as HTML text
def html_encode(bytestring):
	return bytestring.replace(b'&', b'&amp;').replace(b'<', b'&lt;').replace(b'>', b'&gt;')

# send_gophermap(sock, reader, protocol, *, config)
# Send the gophermap in the given reader either as gophermap or HTML
def send_gophermap(sock, reader, protocol, *, config):
	if protocol == Protocol.gopher or protocol == Protocol.gopherplus:
		# Gopher(+) needs no additional translation, send as text
		send_textfile(sock, reader, protocol, config = config)

	elif protocol == Protocol.http:
		# Send header of the HTML file
		sock.sendall(b'<!DOCTYPE html>\n<head><title>Gophermap</title></head><body><p>\n')

		lines = []
		line = bytearray()

		for byte in reader:
			if chr(byte) == '\n':
				# Add to lines and clear
				lines.append(line)
				line = bytearray()

			else:
				# Add to the line
				line.append(byte)

		# If there was no terminating \n, add the line to lines
		if len(line) != 0:
			lines.append(line)

		for line in lines:
			# Translate to html and send it

			# Split into components
			itemtype_name, path, server, port, *_ = line.split(b'\t')
			itemtype = itemtype_name[0:1]
			name = itemtype_name[1:]

			if itemtype == b'i':
				# Text
				sock.sendall(html_encode(name) + b'<br/>\n')

			else:
				# Link

				# TODO: Figure out a heuristic when to pick http:// and when to pick gopher://

				if port == b'70':
					# If port is 70, don't include the port part. This allows interoperability with Idigna
					url = b'http://' + server + b'/' + itemtype + urllib.parse.quote_from_bytes(path).encode('utf-8')
				else:
					url = b'http://' + server + b':' + port + b'/' + itemtype + urllib.parse.quote_from_bytes(path).encode('utf-8')

				sock.sendall(b'<a href="' + url + b'">' + html_encode(name) + b'</a><br/>\n')

		# Send footer of the HTML file
		sock.sendall(b'</p></body></html>')

	else:
		unreachable()

# send_file(sock, reader, protocol, mimetype, *, config)
# Send data from reader over the socket with right encoding for the mimetype
def send_file(sock, reader, protocol, mimetype, *, config):
	if mimetype == 'text/x-gophermap':
		# Send as gophermap (possibly translated into HTML)
		send_gophermap(sock, reader, protocol, config = config)

	elif is_text_from_mimetype(mimetype):
		# Send as text
		send_textfile(sock, reader, protocol, config = config)

	else:
		# Send as binary file
		send_binaryfile(sock, reader, protocol, config = config)

# test_is_cgi(full_path, *, config) → is_cgi
# Tests whether file associated with full_path is CGI
def test_is_cgi(full_path, *, config):
	# Assume anything runnable is CGI
	return os.access(str(full_path), os.X_OK)

# get_file(full_path, *, config)
# Get a file object that can be passed to FileReader, either of file's contents of CGI's output
def get_file(full_path, *, config):
	if test_is_cgi(full_path, config = config):
		# Run CGI and use its output
		proc = subprocess.Popen([str(full_path)], stdout=subprocess.PIPE)
		return proc.stdout
	else:
		# Open file in binary mode
		file = open(str(full_path), 'rb')
		return file

# is_hurl_path(path_raw) → is_hurl
# Returns whether the path is a hURL redirect
def is_hurl_path(path_raw):
	return len(path_raw) >= 4 and path_raw[:4] == 'URL:'

# hurl_redirect(url_raw, *, config) → redirect_page
# Return a HTML page for hURL redirect
def hurl_redirect(url_raw, *, config):
	url_escaped = cgi.escape(url_raw)
	return config.hurl_redirect_page.replace('__raw_url__', url_raw).replace('__escaped_url__', url_escaped)

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

		path_raw, protocol, *rest = get_request(sockreader, config = self.config)

		just_headers = False
		if protocol == Protocol.http:
			selector, just_headers, useragent = rest

		try:
			if is_hurl_path(path_raw):
				url_raw = path_raw[4:]
				log('%s [%s] hURL %s' % (self.address, protocol.name, url_raw))
				reader = StringReader(hurl_redirect(url_raw, config = self.config))

				send_header(self.sock, protocol, Status.ok, 'text/html', config = self.config)
				send_file(self.sock, reader, protocol, 'text/html', config = self.config)

			else:
				path = normalize_path(path_raw, config = self.config)

				try:
					full_path = get_full_path(path, config = self.config)
					mimetype = get_mimetype(full_path, config = self.config)
					file = get_file(full_path, config = self.config)

				except FileNotFoundError:
					log('%s [%s]: Requested path not found: %s' % (self.address, protocol.name, path_raw))
					reader = StringReader('%s not found\n' % path_raw)
					send_header(self.sock, protocol, Status.notfound, 'text/plain', config = self.config)
					if not just_headers:
						send_file(self.sock, reader, protocol, 'text/plain', config = self.config)

				else:
					log('%s [%s] requested path %s' % (self.address, protocol.name, path_raw))
					reader = FileReader(file)

					send_header(self.sock, protocol, Status.ok, mimetype, config = self.config)
					if not just_headers:
						send_file(self.sock, reader, protocol, mimetype, config = self.config)

					file.close()

		except BaseException as err:
			reader = StringReader('Internal server error\n')
			send_header(self.sock, protocol, Status.error, 'text/plain', config = self.config)
			send_file(self.sock, reader, protocol, 'text/plain', config = self.config)
			raise err

		if protocol == Protocol.http:
			log('User agent: %s' % useragent)

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

class IPParseError(OneArgumentException):
	text = 'Error parsing IP: %s'

# read_blacklist(blacklist_file) → blacklist
# Reads the contents of the blacklist file into a form usable by ip_in_ranges()
def read_blacklist(blacklist_file):
	try:
		file = open(str(blacklist_file), 'r')
	except FileNotFoundError:
		return []

	lines = file.read().split('\n')
	file.close()

	blacklist = []
	for line in lines:
		# Comment handling
		if '#' in line:
			line = line[:line.index('#')]

		# Remove surrounding whitespace
		line = line.strip()

		# If an empty line, skip
		if line == '':
			continue

		try:
			ip_range = ipaddress.ip_network(line)
		except ValueError:
			raise IPParseError('Invalid format: ' + line)

		blacklist.append(ip_range)

	return blacklist

# ip_in_ranges(ip, ip_ranges) → in_rages
# Checks whether an ip address is in given ranges
def ip_in_ranges(ip, ip_ranges):
	try:
		ip = ipaddress.ip_address(ip)
	except ValueError:
		raise IPParseError('Invalid format: ' + line)

	for ip_range in ip_ranges:
		if ip in ip_range:
			return True

	return False

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

	# Read blacklist of addresses
	blacklist = read_blacklist(config.blacklist_file)

	while True:
		# Wait for listening sockets to get activity
		events = listening.poll()
		for fd,event in events:
			assert(event == select.POLLIN)
			# Get socket from table established previously
			s = sock_by_fd[fd]
			# Accept and handle the connection
			conn, addr = s.accept()

			# Check if connection is from a blacklisted IP address
			if ip_in_ranges(addr[0], blacklist):
				# It was, skip event
				conn.close()
				log('Connection from blacklisted address %s' % addr[0])
				continue

			# Set timeout for socket
			conn.settimeout(config.socket_timeout)

			threads_controller.spawn_thread(conn, addr[0], config)

if __name__ == '__main__':
	listen(default_config)
