import imaplib
import email.utils
import socket
import ssl

BUFFER_SIZE = 1024
#imap_url = "imap.gmail.com"
#imap_url = 'imap.mailtrap.io'
imap_url = 'localhost'
imap_port=143 #993
imap_ssl_port= 993
box_name='INBOX'
ENDOF='#'
user = 'fuele95@gmail.com'
password = ''


class MyIMAPclient:

    def __init__(self, imap_url = 'localhost', imap_port =143):
        self.connection = socket.socket()
        self.url= imap_url
        self.port=imap_port
        #context = ssl.create_default_context()


        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations("ssl/certs/cert.pem")
            self.connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname='phemailserver')
            self.connection.connect((imap_url, imap_port))

            #self.connection.connect((self.url, self.port))
            received = str(self.connection.recv(BUFFER_SIZE), "utf-8")
            print("received", received)

            password=input("password: ")
            self.login(user, password)
            self.select('INBOX')
            self.fetch()
            self.close()
            self.logout()

        except Exception as e:
            print("ex", e)


    def process_mail(self, mail_list):

        if len(mail_list) != 0:
            for elem in mail_list:

                result, mail_text = elem.split(ENDOF)
                m = email.message_from_string(mail_text)

                if bool(result):
                    print("valore, ",result)
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
            raise ValueError('Error during login phase\n---> ',r)

    def select(self, box_name):
        r = self.send_to_proxy('select\n'+box_name)
        if r != 'OK':
            raise ValueError('Error during select phase\n---> ',r)

    def fetch(self):
        r = self.send_to_proxy('fetch')
        mail_list=[]
        if r == 'OK':
            while True:
                r = str(self.connection.recv(BUFFER_SIZE), "utf-8")
                mail_list.append(r)
                break
                if r != ENDOF:
                    mail_list.append(r)
                else:
                    break
        else:
            raise ValueError('Error during fetch phase\n---> ', r)

        self.process_mail(mail_list)


    def close(self):
        r = self.send_to_proxy('close')
        if r != 'OK':
            raise ValueError('Error during close phase \n---> ',r)


    def logout(self):
        r = self.send_to_proxy('logout')
        if r != 'OK':
            raise ValueError('Error during logout phase\n---> ',r)

    def send_to_proxy(self, to_send):
        self.connection.sendall(bytes(to_send,"utf-8"))
        received = str(self.connection.recv(BUFFER_SIZE), "utf-8")
        return received


MyIMAPclient()