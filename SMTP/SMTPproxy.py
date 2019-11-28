import ssl, smtpd, smtplib, secure_smtpd, email, base64, asyncore
import logging, os
from secure_smtpd import proxy_server
from registration import gen_keys, encrypt_msg, sign_msg


# Authorized domain addresses with their corresponding host
HOSTS = {
    'hotmail': 'smtp-mail.outlook.com',
    'outlook': 'smtp-mail.outlook.com',
    'yahoo': 'smtp.mail.yahoo.com',
    'gmail': 'smtp.gmail.com',
    'studenti.unisa':'smtp.gmail.com',
    'unisa':'smtp.gmail.com',
    'fau': 'smtp-auth.fau.de',
    'cs.fau': 'smtp-auth.fau.de',
    # 'dovecot': 'dovecot.travis.dev'  # for Travis-CI
}

domain = 'smtp.gmail.com'
port = 465
ssl_port = '2525'
fau_tls_port = 587
fau_ssl_port = 465

class MySMTPproxy(proxy_server.ProxyServer):

    def __init__(self, localaddr, remoteaddr, ssl=False, certfile=None, keyfile=None, ssl_version=ssl.PROTOCOL_SSLv23,
                 require_authentication=False, maximum_execution_time=30, process_count=5):
        smtpd.SMTPServer.__init__(self, localaddr, remoteaddr)
        self.logger = logging.getLogger(secure_smtpd.LOG_NAME)
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_version = ssl_version
        self.subprocesses = []
        self.require_authentication = require_authentication
        self.credential_validator = self
        self.ssl = ssl
        self.maximum_execution_time = maximum_execution_time
        self.process_count = process_count
        self.process_pool = None
        self.server = None

    def send_mail(self,sender, recipient, data):
        try:
            email_message = email.message_from_string(data)
            text = email_message.get_payload()
            enc = encrypt_msg(text, recipient)
            email_message.set_payload(base64.b64encode(enc).decode('utf-8'))

            sign = sign_msg(text, self.username)
            email_message['Signature'] = base64.b64encode(sign).decode('utf-8')

            self.server.sendmail(sender, recipient, email_message.as_string())
            self.quit()

        except Exception as e:
            print("ERROR",e)


    def process_message(self, peer, mailfrom, rcpttos, data):
        email_message = email.message_from_string(data)
        print(email_message)
        self.send_mail(mailfrom, rcpttos[0], data)

    def quit(self):
        self.server=None
        self.password=None
        self.username=None

    #Credential Validator
    def validate(self, username, password):
        try:
            self.login(username, password)
        except Exception as e:
            print(e)
            return False
        return True

    def login(self, username, password):
        self.username = username
        self.password = password
        '''
        domains = username.split('@')[1].split('.')[:-1]  # Remove before '@' and remove '.com' / '.be' / ...
        domain = '.'.join(str(d) for d in domains)
        try:
            hostname = HOSTS[domain]
            print(hostname)
            self.server = smtplib.SMTP_SSL(hostname, ssl_port)
            self.server.login(username, password)
            
            if self.server.has_extn('STARTTLS'):
                self.server.starttls()
                self.server.ehlo()  # re-identify ourselves over TLS connection

            if not os.path.exists(self.username):
                os.mkdir(self.username)
                gen_keys(self.username)

            if not os.path.exists(recipient):
                os.mkdir(recipient)
                gen_keys(recipient)

        except KeyError:
            raise ValueError('Error while connecting to the server: '
                             + 'Invalid domain name ' + domain)
        except Exception:
            raise ValueError('Error while connecting to the server: '
                             + 'Invalid credentials: ' + username + " / " + password)
        '''

#Credentials smpt for MailTrap
#user ='4af48ff5bf173f'
#password = ''
#domain = 'smtp.mailtrap.io'


logger = logging.getLogger( secure_smtpd.LOG_NAME )
logger.setLevel(logging.INFO)

server = MySMTPproxy(
    ('127.0.0.1', 1025),
    None,
    require_authentication=True,
    ssl=True,
    certfile='ssl/certs/server.crt',
    keyfile='ssl/certs/server.key',
    #maximum_execution_time = 2.0
    )

server.run()

