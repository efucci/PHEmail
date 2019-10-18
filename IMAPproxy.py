import base64
import email
import imaplib
import socket
from email.mime.text import MIMEText
import ssl
import threading
from crypto_functions import decrypt_msg,verify_sign

# Intercepted commands
COMMANDS = (
    'authenticate',
    'login',
    'logout',
    'select',
    'move',
    'fetch'
)

MAX_CLIENT = 5
IMAP_PORT = 143
IMAP_SSL_PORT= 993
BUFFER_SIZE = 1024



def read_message(imap_url, imap_port, user, password, box_name):
    try:
        connection = imaplib.IMAP4_SSL(imap_url, imap_port)
        connection.login(user, password)
        connection.select(box_name)

        to_send = []

        result, data = connection.uid('search', None, "ALL")

        if result == 'OK':
            for num in data[0].split():

                result, data = connection.uid('fetch', num, '(RFC822)')

                if result == 'OK':

                    email_message = email.message_from_bytes(data[0][1])
                    if email_message['From'] == 'fuele95@gmail.com':
                        try:
                            sign = base64.b64decode(email_message['Signature'])
                            pay = base64.b64decode(email_message.get_payload())
                            dec = decrypt_msg(pay, user)
                            email_message.set_payload(dec)
                            verified = verify_sign(sign, dec, email_message['From'])
                            if verified:

                                print("sign is valid")
                                print('From:' + email_message['From'])
                                print('To:' + email_message['To'])
                                print('Date:' + email_message['Date'])
                                print('Subject:' + str(email_message['Subject']))
                                print('Content: ' + dec)
                            else:
                                print("sign is invalid")
                            to_send.append((email_message, verified))
                        except Exception as e:
                            print(e)

    except Exception as e:
        print(e)

    connection.close()
    connection.logout()

    return to_send


class MyIMAPproxy():

    def __init__(self, port=None, host='', certfile=None, max_client=MAX_CLIENT, verbose=False,
             ipv6=False):
        self.verbose = verbose
        #self.certfile = certfile
        #self.key = key

        if not port:  # Set default port
            port = IMAP_SSL_PORT if certfile else IMAP_PORT

        if not max_client:
            max_client = MAX_CLIENT

        # IPv4 or IPv6
        addr_fam = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.sock = socket.socket(addr_fam, socket.SOCK_STREAM)

        self.sock.bind((host, port))
        self.sock.listen(max_client)

        conn_client, addr = self.sock.accept()
        print('Connection address:', addr)
        data = ('I am ready').encode('utf-8')
        conn_client.send(data)

        received = str(conn_client.recv(1024), "utf-8")

        if received in COMMANDS:
            print(received)


        #emails = read_message('imap.gmail.com', 993, user, password, 'INBOX')
        emails=""
        for i in range(1,3):


            # Create the message
            msg = MIMEText('This is the body of the message '+str(i))
            msg['To'] = email.utils.formataddr(('Recipient', 'recipient@example.com'))
            msg['From'] = email.utils.formataddr(('Author', 'author@example.com'))
            msg['Subject'] = 'Simple test message'
            emails=emails+msg.as_string()+',True#'

        conn_client.send(emails.encode('utf-8'))


        #while 1:
        #    data = conn_client.recv()
        #    if not data: break
        #   print("received data:", data)
            #conn.send(data)  # echo

        #conn_client.close()




imap_proxy = MyIMAPproxy()
