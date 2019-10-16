import email
import smtpd
import asyncore
from mail_functions import send_mail

class MyProxy(smtpd.PureProxy):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        print('Receiving message from:', peer)
        print('Message addressed from:', mailfrom)
        print('Message addressed to  :', rcpttos)
        print('Message length        :', len(data))

        email_message = email.message_from_bytes(data)
        print(email_message)


proxy = MyProxy(('127.0.0.1', 1025), ('mail', 25))

asyncore.loop()
