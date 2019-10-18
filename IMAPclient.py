import imaplib
import email.utils
import socket

#imap_url = "imap.gmail.com"
#imap_url = 'imap.mailtrap.io'
imap_url = 'localhost'
imap_port=143
box_name='INBOX'

user = '4af48ff5bf173f'
password = 'be978723ada37e'

def process_mail(mail_string):

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


#connection = imaplib.IMAP4_SSL(imap_url, imap_port)
connection = socket.socket()
try:
    connection.connect((imap_url, imap_port))
    connection.sendall(bytes('login', "utf-8"))
    received=str(connection.recv(1024), "utf-8")

    connection.send(bytes('login', "utf-8"))
    received = str(connection.recv(1024), "utf-8")
    process_mail(received)
    connection.close()

except Exception as e:
    print(e)

# TO-DO
# parsing della lista della mail
#connection.login(user, password)
    #connection.select(box_name)
   # connection.fetch()



    #result, data = connection.uid('search', None, "ALL")
'''
    if result == 'OK':
        for num in data[0].split():
            result, data = connection.uid('fetch', num, '(RFC822)')
        if result == 'OK':
            email_message = email.message_from_bytes(data[0][1])
            print('From:' + email_message['From'])
            print('To:' + email_message['To'])
            print('Date:' + email_message['Date'])
            print('Subject:' + str(email_message['Subject']))
            print('Content:' + str(email_message.get_payload()[0]))
    connection.close()
    connection.logout()

finally:

    connection.quit()
'''