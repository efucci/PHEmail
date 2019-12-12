import socket

from IMAP import proxy

MAX_CLIENT = 5
IMAP_PORT = 143
IMAP_SSL_PORT = 993 #10023
BUFFER_SIZE = 1024
DEFAULT_KEY = 'secret-proxy'

class MyIMAPproxy(proxy.IMAP_Proxy):

    def __init__(self, port=None, host='', certfile=None, key=DEFAULT_KEY, max_client=MAX_CLIENT, verbose=False,
                 ipv6=False):
        self.verbose = verbose
        self.certfile = certfile
        self.key = key

        if not port:  # Set default port
            port = IMAP_SSL_PORT if certfile else IMAP_PORT

        if not max_client:
            max_client = MAX_CLIENT

        # IPv4 or IPv6
        addr_fam = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.sock = socket.socket(addr_fam, socket.SOCK_STREAM)

        self.sock.bind((host, port))
        self.sock.listen(max_client)
        self.listen()

MyIMAPproxy()