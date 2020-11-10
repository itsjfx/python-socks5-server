import logging
import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, BaseRequestHandler
import sys

logging.basicConfig(level=logging.DEBUG)

# Constants
SOCKS_VERSION = 5
CONNECT = 1
RESERVED = 0
FAILURE = 0xFF
USERNAME_PASSWORD_VERSION = 1
CONNECTION_TIMEOUT = 60 * 15 * 1000

# Buffer sizes
GREETING_SIZE = 2
AUTH_METHOD_SIZE = 1
VERSION_SIZE = 1
ID_LEN_SIZE = 1
PW_LEN_SIZE = 1
CONN_NO_PORT_SIZE = 4
CONN_PORT_SIZE = 2
DOMAIN_SIZE = 1

class AuthMethod:
	NoAuth = 0
	GSSAPI = 1
	UsernamePassword = 2
	Invalid = 0xFF

class StatusCode:
	Success = 0
	GeneralFailure = 1
	NotAllowed = 2
	NetUnreachable = 3
	HostUnreachable = 4
	ConnRefused = 5
	TTLExpired = 6
	CommandNotSupported = 7
	AddressTypeNotSupported = 8

class AddressDataType:
	IPv4 = 1
	DomainName = 3
	IPv6 = 4

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
	pass

class SOCKS5ProxyServer(BaseRequestHandler):
	def setup(self):
		super(SOCKS5ProxyServer, self).setup()
		if not hasattr(self.server, "auth"):
			self.server.auth = False

	def handle(self):
		logging.info('Accepting connection from %s:%s' % self.client_address)

		# Greeting header
		header = self._recv(GREETING_SIZE, self._send_greeting_failure, AuthMethod.Invalid)
		version, nmethods = struct.unpack("!BB", header)
		# Only accept SOCKS5
		if version != SOCKS_VERSION:
			self._send_greeting_failure(self.auth_method)
		# We need at least one method
		if nmethods < 1:
			self._send_greeting_failure(AuthMethod.Invalid)

		# Get available methods
		methods = self._get_available_methods(nmethods)
		logging.debug(f'Received methods {methods}')

		# Accept only USERNAME/PASSWORD auth if we are asking for auth
		# Accept only no auth if we are not asking for USERNAME/PASSWORD
		if (self.server.auth and AuthMethod.UsernamePassword not in set(methods)) or (not self.server.auth and AuthMethod.NoAuth not in set(methods)):
			self._send_greeting_failure(AuthMethod.Invalid)

		# Choose an authentication method and send it to the client
		self._send(struct.pack("!BB", SOCKS_VERSION, self.auth_method))

		# If we are asking for USERNAME/PASSWORD auth verify it
		if self.server.auth:
			self._verify_credentials()

		# Auth done...
		# request
		logging.debug("Successfully authenticated")

		conn_buffer = self._recv(CONN_NO_PORT_SIZE, self._send_failure, StatusCode.GeneralFailure)
		version, cmd, rsv, address_type = struct.unpack("!BBBB", conn_buffer)
		if version != SOCKS_VERSION:
			self._send_greeting_failure(self.auth_method)

		self._address_type = address_type
		logging.debug(f'Handling request with address type: {address_type}')

		if address_type == AddressDataType.IPv4 or address_type == AddressDataType.IPv6: # IPv4 or IPv6
			address_family = socket.AF_INET if address_type == AddressDataType.IPv4 else socket.AF_INET6
			minlen = 4 if address_type == AddressDataType.IPv4 else 16
			raw = self._recv(minlen, self._send_failure, StatusCode.GeneralFailure) # Raw IP address bytes

			# Convert the IP address from binary to text
			try:
				address = socket.inet_ntop(address_family, raw)
			except Exception as err:
				logging.debug(f'Could not convert packed IP {raw} to string')
				logging.error(err)
				self._send_failure(StatusCode.GeneralFailure)
		elif address_type == AddressDataType.DomainName: # Domain name
			domain_buffer = self._recv(DOMAIN_SIZE, self._send_failure, StatusCode.GeneralFailure)
			domain_length = domain_buffer[0]
			if domain_length > 255: # Invalid
				self._send_failure(StatusCode.GeneralFailure)
			address = self._recv(domain_length, self._send_failure, StatusCode.GeneralFailure)
		else:
			self._send_failure(StatusCode.AddressTypeNotSupported)
		port_buffer = self._recv(CONN_PORT_SIZE, self._send_failure, StatusCode.GeneralFailure)
		port = struct.unpack('!H', port_buffer)[0]

		# Translate our address and port into data from which we can create a socket connection
		try:
			remote_info = socket.getaddrinfo(address, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
			# Pick the first one returned, probably IPv6 if IPv6 is available or IPv4 if not
			# TO-DO: Try as many as possible in a loop instead of picking only the first returned
			remote_info = remote_info[0]
		except Exception as err: # There's no suitable errorcode in RFC1928 for DNS lookup failure
			logging.error(err)
			self._send_failure(StatusCode.GeneralFailure)
		
		af, socktype, proto, _, sa = remote_info

		if cmd != CONNECT: # We only support connect
			self._send_failure(StatusCode.CommandNotSupported)

		if rsv != RESERVED: # Malformed packet
			self._send_failure(StatusCode.GeneralFailure)

		# Connect to the socket
		try:
			self._remote = socket.socket(af, socktype, proto)
			self._remote.connect(sa)
			bind_address = self._remote.getsockname()
			logging.info(f'Connected to {address} {port}')

			# Get the bind address and port
			addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
			port = bind_address[1]
			logging.debug(f'Bind address {addr} {port}')
		except Exception as err:
			logging.error(err)
			# TO-DO: Get the actual failure code instead of giving ConnRefused each time
			self._send_failure(StatusCode.ConnRefused)

		# TO-DO: Are the BND.ADDR and BND.PORT returned correct values?
		self._send(struct.pack("!BBBBIH", SOCKS_VERSION, StatusCode.Success, RESERVED, AddressDataType.IPv4, addr, port))

		# Establish data exchange
		self._exchange_loop(self.request, self._remote)
		self._exit(True)

	@property
	def auth_method(self):
		"""Gives us the authentication method we will use"""
		return AuthMethod.UsernamePassword if self.server.auth else AuthMethod.NoAuth

	def _send(self, data):
		"""Convenience method to send bytes to a client"""
		return self.request.sendall(data)

	def _recv(self, bufsize, failure_method=False, code=False):
		"""Convenience method to receive bytes from a client
			If bufsize is less than the size of the data received calls failure_method with code as a parameter and kills the thread"""
		buf = self.request.recv(bufsize)
		if len(buf) < bufsize:
			if failure_method and code:
				failure_method(code)
			elif failure_method:
				failure_method()
			else:
				self._exit() # Kill thread if we aren't calling the failure methods (they already do this)
		return buf

	def _shutdown_client(self):
		"""Convenience method to shutdown and close the connection with a client"""
		self.server.shutdown_request(self.request)

	def _exit(self, dontExit=False):
		"""Convenience method to exit the thread and cleanup any connections"""
		self._shutdown_client()
		if hasattr(self, "_remote"):
			self._remote.shutdown(socket.SHUT_RDWR)
			self._remote.close()
		if not dontExit:
			sys.exit()

	def _get_available_methods(self, n):
		"""Receive the methods a client supported and return them as a list"""
		methods = []
		for i in range(n):
			methods.append(ord(self._recv(AUTH_METHOD_SIZE, self._send_greeting_failure, AuthMethod.Invalid)))
		return methods

	def _verify_credentials(self):
		"""Verify the credentials of a client and send a response relevant response
			and possibly close the connection + thread if unauthenticated
		"""
		version = ord(self._recv(VERSION_SIZE))
		if version != USERNAME_PASSWORD_VERSION:
			logging.error(f'USERNAME_PASSWORD_VERSION did not match')
			self._send_authentication_failure(FAILURE)

		username_len = self._recv(ID_LEN_SIZE, self._send_authentication_failure, FAILURE)
		username = self._recv(ord(username_len), self._send_authentication_failure, FAILURE)

		password_len = self._recv(PW_LEN_SIZE, self._send_authentication_failure, FAILURE)
		password = self._recv(ord(password_len), self._send_authentication_failure, FAILURE)

		if username.decode('utf-8') == self.server.auth[0] and password.decode('utf-8') == self.server.auth[1]:
			self._send(struct.pack("!BB", USERNAME_PASSWORD_VERSION, StatusCode.Success))
			return True

		logging.error(f'Authentication failed')
		self._send_authentication_failure(FAILURE)

	def _send_greeting_failure(self, code):
		"""Convinence method to send a failure message to a client in the greeting stage"""
		self._send(struct.pack("!BB", SOCKS_VERSION, code))
		self._exit()

	def _send_authentication_failure(self, code):
		"""Convinence method to send a failure message to a client in the authentication stage"""
		self._send(struct.pack("!BB", USERNAME_PASSWORD_VERSION, code))
		self._exit()

	def _send_failure(self, code):
		"""Convinence method to send a failure message to a client in the socket stage"""
		address_type = self._address_type if hasattr(self, "_address_type") else AddressDataType.IPv4
		self._send(struct.pack("!BBBBIH", SOCKS_VERSION, code, RESERVED, address_type, 0, 0))
		self._exit()

	# TO-DO: Rewrite this function
	def _exchange_loop(self, client, remote):
		while True:
			# Wait until client or remote is available for read
			# Alternatively use poll() instead of select() due to these reasons
			# https://github.com/rofl0r/microsocks/commit/31557857ccce5e4fdd2cfdae7ab640d589aa2b41
			# May not be ideal for a cross platform implementation however
			r, w, e = select.select([client, remote], [], [], CONNECTION_TIMEOUT)

			# Kill inactive/unused connections
			if not r and not w and not e:
				self._send_failure(StatusCode.TTLExpired)

			if client in r:
				data = client.recv(4096)
				if remote.send(data) <= 0:
					break

			if remote in r:
				data = remote.recv(4096)
				if client.send(data) <= 0:
					break


if __name__ == '__main__':
	# TO-DO: Add CLI args for options
	# Add to seperate file?
	with ThreadingTCPServer(('0.0.0.0', 1080), SOCKS5ProxyServer) as server:
		server.auth = ("username", "password")
		#server.auth = False
		server.serve_forever()
