import logging
import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, BaseRequestHandler

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

class SocksProxy(BaseRequestHandler):
	def handle(self):
		logging.info('Accepting connection from %s:%s' % self.client_address)

		# Greeting header
		header = self.request.recv(GREETING_SIZE)
		if len(header) < GREETING_SIZE:
			self._send_greeting_failure(AuthMethod.Invalid)
			return
		version, nmethods = struct.unpack("!BB", header)
		# Only accept SOCKS5
		if version != SOCKS_VERSION:
			self._send_greeting_failure(self.auth_method)
			return
		# We need at least one method
		if nmethods < 1:
			self._send_greeting_failure(AuthMethod.Invalid)
			return

		# Get available methods
		methods = self._get_available_methods(nmethods)
		logging.debug(f'Received methods {methods}')

		if not hasattr(self.server, "auth"):
			self.server.auth = False

		# Accept only USERNAME/PASSWORD auth if we are asking for auth
		# Accept only no auth if we are not asking for USERNAME/PASSWORD
		if (self.server.auth and AuthMethod.UsernamePassword not in set(methods)) or (not self.server.auth and AuthMethod.NoAuth not in set(methods)):
			self._send_greeting_failure(AuthMethod.Invalid)
			return

		# Choose an authentication method and send it to the client
		self.request.sendall(struct.pack("!BB", SOCKS_VERSION, self.auth_method))

		# If we are asking for USERNAME/PASSWORD auth verify it
		if self.server.auth and not self._verify_credentials():
			return

		# Auth done...
		# request
		logging.debug("Successfully authenticated")
		
		conn_buffer = self.request.recv(CONN_NO_PORT_SIZE)
		if len(conn_buffer) < CONN_NO_PORT_SIZE:
			self._send_failure(StatusCode.GeneralFailure)
			return
		
		version, cmd, rsv, address_type = struct.unpack("!BBBB", conn_buffer)
		if version != SOCKS_VERSION:
			self._send_greeting_failure(self.auth_method)
			return

		self._address_type = address_type
		logging.debug(f'Handling request with address type: {address_type}')

		if address_type == AddressDataType.IPv4 or address_type == AddressDataType.IPv6: # IPv4 or IPv6
			address_family = socket.AF_INET if address_type == AddressDataType.IPv4 else socket.AF_INET6
			minlen = 4 if address_type == AddressDataType.IPv4 else 16
			raw = self.request.recv(minlen) # Raw IP address bytes
			if len(raw) < minlen:
				self._send_failure(StatusCode.GeneralFailure)
				return

			# Convert the IP address from binary to text
			try:
				address = socket.inet_ntop(address_family, raw)
			except Exception as err:
				logging.debug(f'Could not convert packed IP {raw} to string')
				logging.error(err)
				self._send_failure(StatusCode.GeneralFailure)
				return
		elif address_type == AddressDataType.DomainName: # Domain name
			domain_buffer = self.request.recv(DOMAIN_SIZE)
			if len(domain_buffer) < DOMAIN_SIZE:
				self._send_failure(StatusCode.GeneralFailure)
				return
			domain_length = domain_buffer[0]
			if domain_length > 255: # Invalid
				self._send_failure(StatusCode.GeneralFailure)
				return
			address = self.request.recv(domain_length)
		else:
			self._address_type = AddressDataType.IPv4 # Set it to IPv4 for the failure message
			self._send_failure(StatusCode.AddressTypeNotSupported)
			return
		port_buffer = self.request.recv(CONN_PORT_SIZE)
		if len(port_buffer) < CONN_PORT_SIZE:
			self._send_failure(StatusCode.GeneralFailure)
			return
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
			return
		
		af, socktype, proto, _, sa = remote_info

		if cmd != CONNECT: # We only support connect
			self._send_failure(StatusCode.CommandNotSupported)
			return

		if rsv != RESERVED: # Malformed packet
			self._send_failure(StatusCode.GeneralFailure)
			return

		# Connect to the socket
		try:
			remote = socket.socket(af, socktype, proto)
			remote.connect(sa)
			bind_address = remote.getsockname()
			logging.info(f'Connected to {address} {port}')

			# Get the bind address and port
			addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
			port = bind_address[1]
			logging.debug(f'Bind address {addr} {port}')
		except Exception as err:
			logging.error(err)
			# TO-DO: Get the actual failure code instead of giving ConnRefused each time
			self._send_failure(StatusCode.ConnRefused)
			return

		# TO-DO: Are the BND.ADDR and BND.PORT returned correct values?
		self.request.sendall(struct.pack("!BBBBIH", SOCKS_VERSION, StatusCode.Success, RESERVED, AddressDataType.IPv4, addr, port))

		# Establish data exchange
		self._exchange_loop(self.request, remote)
		self._close()

	@property
	def auth_method(self):
		return AuthMethod.UsernamePassword if self.server.auth else AuthMethod.NoAuth

	def _close(self):
		self.server.close_request(self.request)

	def _get_available_methods(self, n):
		methods = []
		for i in range(n):
			methods.append(ord(self.request.recv(1)))
		return methods

	def _verify_credentials(self):
		version = ord(self.request.recv(VERSION_SIZE))
		if version != USERNAME_PASSWORD_VERSION:
			logging.error(f'USERNAME_PASSWORD_VERSION did not match')
			self._send_authentication_failure(FAILURE)
			return False

		username_len = ord(self.request.recv(ID_LEN_SIZE))
		username = self.request.recv(username_len).decode('utf-8')

		password_len = ord(self.request.recv(PW_LEN_SIZE))
		password = self.request.recv(password_len).decode('utf-8')

		if username == self.server.auth[0] and password == self.server.auth[1]:
			self.request.sendall(struct.pack("!BB", USERNAME_PASSWORD_VERSION, StatusCode.Success))
			return True

		logging.error(f'Authentication failed')
		self._send_authentication_failure(FAILURE)
		return False

	def _send_greeting_failure(self, code):
		self.request.sendall(struct.pack("!BB", SOCKS_VERSION, code))
		self._close()

	def _send_authentication_failure(self, code):
		self.request.sendall(struct.pack("!BB", USERNAME_PASSWORD_VERSION, code))
		self._close()

	def _send_failure(self, code):
		self.request.sendall(struct.pack("!BBBBIH", SOCKS_VERSION, code, RESERVED, self._address_type, 0, 0))
		self._close()

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
	with ThreadingTCPServer(('0.0.0.0', 1080), SocksProxy) as server:
		#server.auth = ("username", "password")
		#server.auth = False
		server.serve_forever()
