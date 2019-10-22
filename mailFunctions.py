import imaplib
import smtplib

from email.mime.text import MIMEText
import email.mime
import email

from cryptoFunctions import *
import os
import base64
import logging

# set up logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



def send_mail(smtp_ssl_host, smtp_ssl_port, user, password, recipient, data):

    server = smtplib.SMTP_SSL(smtp_ssl_host, smtp_ssl_port)
    #server = smtplib.SMTP(smtp_ssl_host, smtp_ssl_port)
    sender = 'Eleonora Fucci'

    if server.has_extn('STARTTLS'):
        server.starttls()
        server.ehlo() # re-identify ourselves over TLS connection

    if not os.path.exists(user):
        os.mkdir(user)
        gen_keys(user)

    if not os.path.exists(recipient):
        os.mkdir(recipient)
        gen_keys(recipient)

    email_message = email.message_from_bytes(data)
    text=email_message.get_payload()
    enc = encrypt_msg(text, recipient)
    email_message.set_payload(base64.b64encode(enc).decode('utf-8'))

    sign = sign_msg(text,user)
    email_message['Signature'] = base64.b64encode(sign).decode('utf-8')

    server.login(user, password)
    server.sendmail(sender, recipient, email_message.as_string())

    server.quit()



def read_message(imap_url, imap_port, user, password, box_name):

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


'''
subject= 'Hello'
smtp_ssl_host ='smtp.mailtrap.io' #'smtp.gmail.com' #' faui13mail.cs.fau.de'
smtp_ssl_port = 2525 #465  # SSL/TLS port
sender = 'fuele95@gmail.com'   #'test@i13.informatik.uni-erlangen.de' #root@faui13phemail.informatik.uni-erlangen.de
target = 'fuele95@gmail.com'  #recipients list

message='Hi, how are you today?'


#user = input("user: ")
#password = input("password: ")
#target = input("recipient: ")
#message= input("text: ")

send_mail(smtp_ssl_host, smtp_ssl_port, user, password, target ,message, subject)

#imap_url = "imap.gmail.com"
imap_url = 'imap.mailtrap.io'
imap_port=993
box_name='INBOX'
#read_message(imap_url, imap_port,box_name)
'''
