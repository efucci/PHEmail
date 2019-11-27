import base64
import email
import imaplib
import socket
import ssl
import threading


from crypto_utils import decrypt_msg, verify_sign

ENDOF = '#'
user = 'fuele95@gmail.com'

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
    'studenti.unisa':'imap.gmail.com',
    'unisa':'imap.gmail.com',
    'fau': 'faumail.fau.de',
    'cs.fau': 'faumail.fau.de',
    # 'dovecot': 'dovecot.travis.dev'  # for Travis-CI
}

MAX_CLIENT = 5
IMAP_PORT = 143
IMAP_SSL_PORT = 993 #10023
BUFFER_SIZE = 1024

class MyIMAPproxy():

    def __init__(self, port=None, host='', max_client=MAX_CLIENT, verbose=False,
                 ipv6=False):
        self.verbose = verbose
        if not port:
            port = IMAP_PORT

        if not max_client:
            max_client = MAX_CLIENT

        # IPv4 or IPv6
        addr_fam = socket.AF_INET6 if ipv6 else socket.AF_INET

        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile="ssl/certs/cert.pem")

        self.sock = socket.socket()
        self.sock = socket.socket(addr_fam, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(max_client)
        self.client_listener()


    def client_listener(self):
        while True:
            try:
                ssock, addr = self.sock.accept()
                connstream = self.context.wrap_socket(ssock, server_side=True)

                # Connect the proxy with the client
                threading.Thread(target=self.connection_client, args=(connstream,)).start()
            except KeyboardInterrupt:
                break
            except ssl.SSLError as e:
                raise e

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
            print('Server ok')
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
        self.username = username
        self.password = password
        domains = username.split('@')[1].split('.')[:-1]  # Remove before '@' and remove '.com' / '.be' / ...
        domain = '.'.join(str(d) for d in domains)
        try:
            hostname = HOSTS[domain]
            self.conn_server = imaplib.IMAP4_SSL(hostname)
            self.conn_server.login(username, password)

        except KeyError:
            self.send_to_client('Unknown hostname')
            raise ValueError('Error while connecting to the server: '
                             + 'Invalid domain name ' + domain)

        except imaplib.IMAP4.error:
            self.send_to_client("Login failed ---> Invalid credentials:"+ username + " / " + password)
            raise ValueError('Error while connecting to the server: '
                             + 'Invalid credentials: ' + username + " / " + password)
        self.send_to_client("OK")

    def select(self, box_name):
        if self.conn_server is not None:
            try:
                self.conn_server.select(box_name)
            except Exception:
                self.send_to_client("Invalid mail box name")
                raise ValueError('Error while selecting mail box:' + 'Invalid name: ' + box_name)
            self.send_to_client("OK")

        else:
            self.send_to_client("Error while selecting mail box: you need to login first!")

    def fetch(self):
        if self.conn_server is not None:
            try :
                self.read_message()
            except Exception as e:
                self.send_to_client(str(e))
        else:
            self.send_to_client("Error during fetch phase: you need to login first!")


    def close(self):
        if self.conn_server is not None:
            self.conn_server.close()
            self.send_to_client("OK")
        else:
            self.send_to_client("Error while closing connection: you need to login first!")

    def logout(self):
        if self.conn_server is not None:
            self.conn_server.logout()
            self.send_to_client("OK")
        else:
            self.send_to_client("Error during logout phase: you need to login first!")

    def read_message(self):
        try:
            result, data = self.conn_server.uid('search', None, "ALL")
            #to_send = ""
            if result == 'OK':
                self.send_to_client('OK')
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

                                self.send_to_client(str(verified)+ENDOF+email_message.as_string())
                                break
                                #to_send = to_send + email_message.as_string() + "|" + str(verified) + ENDOF
                            except Exception as e:
                                print(e)

                #self.send_to_client(ENDOF)
        except Exception as e:
            print(e)


MyIMAPproxy()
