import smtplib, getpass
import email.utils
from email.mime.text import MIMEText



# Create the message
#msg = MIMEText('Hi, how are you? :)')
#msg['To'] = email.utils.formataddr(('Recipient', 'fuele95@gmail.com'))
#msg['From'] = email.utils.formataddr(('Author', 'fuele95@gmail.com'))
#msg['Subject'] = 'Simple test message'


try:
    server = smtplib.SMTP_SSL('localhost', 2525)
    server.set_debuglevel(True)

    if server.has_extn('STARTTLS'):
        server.starttls()
        server.ehlo()  # re-identify ourselves over TLS connection

     # show communication with the server
    username = input('username: ')
    password = getpass.getpass('password: ')

    server.login(username, password=password)
    mail_to = input('recipient: ')
    subject = input('Write subject: ')
    textmail = input('Write text: ')
    msg = MIMEText(textmail)
    msg['From'] = username
    msg['To'] = mail_to
    msg['Subject'] = subject
    server.sendmail(username, mail_to , msg.as_string())
    server.quit()

except smtplib.SMTPAuthenticationError:
    print('Login failed: password or username invalid!')
except Exception as e:
    print(f'Other error occurred: {e}')


