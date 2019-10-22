import base64
import email
import os
import smtpd
import asyncore
import smtplib
from cryptoFunctions import gen_keys, encrypt_msg, sign_msg
from mailFunctions import send_mail

#Credentials smpt for MailTrap
user ='4af48ff5bf173f'
password = 'be978723ada37e'
address = 'smtp.mailtrap.io'
domain = 'smtp.gmail.com'
port = 465 #'2525'


class MySMTPproxy(smtpd.PureProxy):

    def send_mail(self, smtp_ssl_host, smtp_ssl_port, user, password, recipient, data):
        try:
            server = smtplib.SMTP_SSL(self, smtp_ssl_host, smtp_ssl_port)
            # server = smtplib.SMTP(smtp_ssl_host, smtp_ssl_port)
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

            email_message = email.message_from_bytes(data)
            text = email_message.get_payload()
            enc = encrypt_msg(text, recipient)
            email_message.set_payload(base64.b64encode(enc).decode('utf-8'))

            sign = sign_msg(text, user)
            email_message['Signature'] = base64.b64encode(sign).decode('utf-8')

            server.login(user, password)
            server.sendmail(sender, recipient, email_message.as_string())

            server.quit()
        except Exception as e:
            print(e)



    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):

        email_message = email.message_from_bytes(data)
        print(email_message)
        print(domain, port, mailfrom,password,rcpttos,data)
        self.send_mail(domain, port, user, password, rcpttos[0], data)


proxy = MySMTPproxy(('127.0.0.1', 1025), ('mail', 25))

asyncore.loop()
