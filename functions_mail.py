import imaplib
import smtplib
from email.mime.text import MIMEText
import email.mime
import email

from crypto_functions import *
import os
import base64
import logging

# set up logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



def send_mail(smtp_ssl_host, smtp_ssl_port, user, password, recipient, text, subject):

    server = smtplib.SMTP_SSL(smtp_ssl_host, smtp_ssl_port)
    if server.has_extn('STARTTLS'):
        server.starttls()
        server.ehlo() # re-identify ourselves over TLS connection

    if not os.path.exists(user):
        os.mkdir(user)
        gen_keys(user)


    enc = encrypt_msg(text, recipient)
    msg = MIMEText(base64.b64encode(enc).decode('utf-8'))

    msg['Subject'] = subject
    #msg['From'] = email.utils.formataddr(('Author',user))
    #msg['To'] = email.utils.formataddr(('Recipient',recipient))
    msg['From'] = user
    msg['To'] = recipient
    sign=sign_msg(text,user)
    msg['Signature'] = base64.b64encode(sign).decode('utf-8')

    server.login(user, password)
    server.sendmail(sender, recipient, msg.as_string())

    server.quit()


def read_message(imap_url,imap_port, box_name):

    connection = imaplib.IMAP4_SSL(imap_url, imap_port)
    connection.login(user, password)
    connection.select(box_name)

    result, data = connection.uid('search', None, "ALL")
    if result == 'OK':
        for num in data[0].split():

            result, data = connection.uid('fetch', num, '(RFC822)')

            if result == 'OK':

                email_message = email.message_from_bytes(data[0][1])
                if email_message['From'] == 'fuele95@gmail.com':
                    sign=base64.b64decode(email_message['Signature'])
                    pay = base64.b64decode(email_message.get_payload())
                    dec = decrypt_msg(pay, user)

                    if verify_sign(sign, dec, email_message['From']):

                        print("sign is valid")
                        print('From:' + email_message['From'])
                        print('To:' + email_message['To'])
                        print('Date:' + email_message['Date'])
                        print('Subject:' + str(email_message['Subject']))
                        print('Content: ' + dec)
                    else:
                        print("sign is invalid")



        connection.close()
        connection.logout()



subject= 'Hello'
smtp_ssl_host = 'smtp.gmail.com' #' faui13mail.cs.fau.de'
smtp_ssl_port = 465  # SSL/TLS port
sender = 'fuele95@gmail.com'   #'test@i13.informatik.uni-erlangen.de' #root@faui13phemail.informatik.uni-erlangen.de
target = 'fuele95@gmail.com'  #recipients list

#message='Hi, how are you today?'


user = input("user: ")
password = input("password: ")
target = input("recipient: ")
message= input("text: ")

send_mail(smtp_ssl_host, smtp_ssl_port, user, password, target ,message, subject)

imap_url = "imap.gmail.com"
imap_port=993
box_name='INBOX'
read_message(imap_url, imap_port,box_name)
