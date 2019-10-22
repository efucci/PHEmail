import base64
import email
import imaplib
import socket
import ssl
import threading
import time

from cryptoFunctions import decrypt_msg, verify_sign

ENDOF = '#'
user = ''

# Intercepted commands
COMMANDS = (
    'authenticate',
    'login',
    'logout',
    'select',
    'close',
    'fetch'
)

# Authorized domain addresses with their corresponding host
HOSTS = {
    'hotmail': 'imap-mail.outlook.com',
    'outlook': 'imap-mail.outlook.com',
    'yahoo': 'imap.mail.yahoo.com',
    'gmail': 'imap.gmail.com',
    # 'dovecot': 'dovecot.travis.dev'  # for Travis-CI
}

MAX_CLIENT = 5
IMAP_PORT = 143
IMAP_SSL_PORT = 993
BUFFER_SIZE = 1024

class MyIMAPproxy():


    def __init__(self, port=None, host='', max_client=MAX_CLIENT, verbose=False,
                 ipv6=False):
        self.verbose = verbose
        if not port:
            port = IMAP_SSL_PORT

        if not max_client:
            max_client = MAX_CLIENT

        # IPv4 or IPv6
        addr_fam = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.sock = socket.socket(addr_fam, socket.SOCK_STREAM)

        self.sock.bind((host, port))
        self.sock.listen(max_client)
        self.client_listener()


    def client_listener(self):
        while True:
            try:
                ssock, addr = self.sock.accept()
                # Connect the proxy with the client
                threading.Thread(target=self.connection_client, args=(ssock,)).start()
            except KeyboardInterrupt:
                break
            except ssl.SSLError as e:
                raise

        if self.sock:
            self.sock.close()

    def connection_client(self, ssock):
        Connection(ssock, self.verbose)


class Connection:

    def __init__(self, conn_socket, verbose=False):
        self.verbose = verbose
        self.conn_client = conn_socket
        self.conn_server = None

        try:
            self.send_to_client('OK Service Ready')  # Server greeting
            self.listen_client()
        except ssl.SSLError:
            pass
        except (BrokenPipeError, ConnectionResetError):
            print('Connections closed')
        except ValueError as e:
            print('[ERROR]', e)

        if self.conn_client:
            self.conn_client.close()

    def listen_client(self):
        """ Listen commands from the client """

        while self.listen_client:
            request = str(self.conn_client.recv(BUFFER_SIZE), "utf-8")
            request = request.split("\n")
            print(request[0])
            print(request)

            if request[0] not in COMMANDS:

                # Not a correct request
                self.send_to_client('Incorrect request')
                raise ValueError('Error while listening the client: '
                                 + request[0] + ' contains no command')
            else:
                self.command(request[0], request)

    def command(self, comm, request):
        if len(request) == 1:
            getattr(self,comm)()
        elif len(request) == 2:
            getattr(self, comm)(request[1])
        else:
            getattr(self, comm)(request[1],request[2])

    def send_to_client(self, text):
        self.conn_client.send(text.encode('utf-8'))

    def login(self, username, password):
        domains = username.split('@')[1].split('.')[:-1]  # Remove before '@' and remove '.com' / '.be' / ...
        domain = ' '.join(str(d) for d in domains)
        try:
            hostname = HOSTS[domain]
            self.conn_server = imaplib.IMAP4_SSL(hostname)
            self.conn_server.login(username, password)
            self.send_to_client("OK")

        except KeyError:
            self.send_to_client('Unknown hostname')
            raise ValueError('Error while connecting to the server: '
                             + 'Invalid domain name ' + domain)

        except imaplib.IMAP4.error:
            self.send_to_client("Login failed ---> Invalid credentials:"+ username + " / " + password)
            raise ValueError('Error while connecting to the server: '
                             + 'Invalid credentials: ' + username + " / " + password)
        self.send_to_client("Successful login")

    def select(self, box_name):
        try:
            self.conn_server.select(box_name)
            self.send_to_client("OK")
        except Exception:
            self.send_to_client("Invalid mail box name")
            raise ValueError('Error while selecting mail box:' + 'Invalid name: ' + box_name)

    def fetch(self):
        try :
            mails_list = self.read_message()
            self.send_to_client('OK\n',mails_list)
        except Exception as e:
            self.send_to_client(str(e))

    def close(self):
        self.conn_server.close()
        self.conn_client.close()
        self.send_to_client("OK")

    def logout(self):
        self.conn_server.logout()
        self.send_to_client("OK")

    def read_message(self):
        try:
            result, data = self.conn_server.uid('search', None, "ALL")
            to_send = ""

            if result == 'OK':
                for num in data[0].split():

                    result, data = self.conn_server.uid('fetch', num, '(RFC822)')

                    if result == 'OK':
                        email_message = email.message_from_bytes(data[0][1])
                        if email_message['From'] == 'fuele95@gmail.com':
                            try:
                                sign = base64.b64decode(email_message['Signature'])
                                pay = base64.b64decode(email_message.get_payload())
                                dec = decrypt_msg(pay, user)
                                email_message.set_payload(dec)
                                verified = verify_sign(sign, dec, email_message['From'])

                                to_send = to_send + email_message.as_string() + str(verified) + ENDOF
                            except Exception as e:
                                print(e)

        except Exception as e:
            print(e)

        return to_send


MyIMAPproxy()
