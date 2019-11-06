import base64
import email
import os
import smtpd
import asyncore
import smtplib

import logging
import secure_smtpd

from cryptoFunctions import gen_keys, encrypt_msg, sign_msg


#Credentials smpt for MailTrap
#user ='4af48ff5bf173f'
password = ''
#domain = 'smtp.mailtrap.io'
domain = 'smtp.gmail.com'
port = 465 #'2525'


class MySMTPproxy(secure_smtpd.proxy_server.ProxyServer):

    def send_mail(self, smtp_ssl_host, smtp_ssl_port, user, password, recipient, data):
        try:
            server = smtplib.SMTP_SSL(smtp_ssl_host, smtp_ssl_port)
            #server = smtplib.SMTP(smtp_ssl_host, smtp_ssl_port)
            sender = 'Eleonora Fucci'

            if server.has_extn('STARTTLS'):
                server.starttls()
                server.ehlo()  # re-identify ourselves over TLS connection

            if not os.path.exists(user):
                os.mkdir(user)
                gen_keys(user)

            if not os.path.exists(recipient):
                os.mkdir(recipient)
                gen_keys(recipient)

            email_message = email.message_from_string(data)
            print('I am here 1')
            text = email_message.get_payload()
            enc = encrypt_msg(text, recipient)
            email_message.set_payload(base64.b64encode(enc).decode('utf-8'))

            sign = sign_msg(text, user)
            email_message['Signature'] = base64.b64encode(sign).decode('utf-8')
            print('I am here 2')
            server.login(user, password)
            print('I am here 3')
            server.sendmail(sender, recipient, email_message.as_string())
            print('I am here 4')
            server.quit()
            print('I am here 5')

        except Exception as e:
            print("ERROR",e)


    def process_message(self, peer, mailfrom, rcpttos, data):
        print('email ricevuta:\n')
        email_message = email.message_from_string(data)
        print(email_message)
        password = '' #to change
        self.send_mail(domain, port, mailfrom, password, rcpttos[0], data)

logger = logging.getLogger( secure_smtpd.LOG_NAME )
logger.setLevel(logging.INFO)
'''
proxy = MySMTPproxy(('127.0.0.1', 1025), ('mail', 25), ssl=True,
certfile='ssl/certs.pem',)
#keyfile='examples/server.key',)
#credential_validator=FakeCredentialValidator(),)
proxy.run()
#asyncore.loop()
'''

server = MySMTPproxy(
    ('127.0.0.1', 1025),
    None,
    require_authentication=True,
    ssl=True,
    certfile='ssl/certs/server.crt',
    keyfile='ssl/certs/server.key',
    credential_validator=secure_smtpd.FakeCredentialValidator(),
    maximum_execution_time = 2.0
    )

server.run()