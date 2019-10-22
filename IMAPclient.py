import imaplib
import email.utils
import socket
import time

BUFFER_SIZE = 1024
#imap_url = "imap.gmail.com"
#imap_url = 'imap.mailtrap.io'
imap_url = 'localhost'
imap_port=143 #993
box_name='INBOX'

user = 'fuele95@gmail.com'
password = 'be978723ada37e'


class MyIMAPclient:

    def __init__(self, imap_url = 'localhost', imap_port =993):
        self.connection = socket.socket()
        self.url= imap_url
        self.port=imap_port

        try:
            self.connection.connect((self.url, self.port))
            received = str(self.connection.recv(BUFFER_SIZE), "utf-8")
            print("received", received)

            #self.login(user, password)
            #self.select('INBOX')
            self.fetch()
            self.close()
            self.logout()

        except Exception as e:
            print("ex",e)


    def process_mail(self, mail_string):

        mail_list = []
        for elem in mail_string.split('#'):
            pair = elem.split(',')
            if len(pair) > 1:
                mail_list.append(pair)

        if len(mail_list) != 0:

            for data in mail_list:

                if data[1]:
                    m=email.message_from_string(data[0])
                    print("Sign is valid\n")
                    #email_message = email.message_from_bytes(data[0][1])
                    print('From:' + m['From'])
                    print('To:' + m['To'])
                    print('Subject:' + m['Subject'])
                    print('Content:' + m.get_payload())
                else:
                    print('Sign is invalid\n')
                    print('Subject:' + str(m['Subject']))
                    print('Content:' + str(m.get_payload()))

        else:
            print('This mail box is empty')


    def login(self, user, password):
        r = self.send_to_proxy('login\n' + user + '\n' + password)
        if r != 'OK':
            raise ValueError('Error during login phase',r)

    def select(self, box_name):
        r = self.send_to_proxy('select\n'+box_name)
        if r != 'OK':
            raise ValueError('Error during select phase\n',r)

    def fetch(self):
        r = self.send_to_proxy('fetch').split('\n')
        if r[0] != 'OK':
            raise ValueError('Error during fetch phase\n',r)
        else:
            self.process_mail(r[1])
    #connection = imaplib.IMAP4_SSL(imap_url, imap_port)

    def close(self):
        r = self.send_to_proxy('close')
        if r != 'OK':
            raise ValueError('Error during close phase',r)


    def logout(self):
        r = self.send_to_proxy('logout')
        if r != 'OK':
            raise ValueError('Error during logout phase',r)

    def send_to_proxy(self, to_send):
        self.connection.sendall(bytes(to_send,"utf-8"))
        received = str(self.connection.recv(BUFFER_SIZE), "utf-8")
        return received


MyIMAPclient()