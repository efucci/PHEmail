import smtplib
import email.utils
from email.mime.text import MIMEText



# Create the message
msg = MIMEText('This is the body of the message.')
msg['To'] = email.utils.formataddr(('Recipient', 'recipient@example.com'))
msg['From'] = email.utils.formataddr(('Author', 'author@example.com'))
msg['Subject'] = 'Simple test message'


try:
    server = smtplib.SMTP_SSL('localhost', 1025)
    #server.set_debuglevel(1)

    if server.has_extn('STARTTLS'):
        server.starttls()
        server.ehlo()  # re-identify ourselves over TLS connection

    server.set_debuglevel(True)  # show communication with the server
    server.login('author@gmail.com', 'foobar')

    server.sendmail('author@example.com', ['recipient@example.com'], msg.as_string())
    #server.sendmail('fuele95@gmail.com',['fuele95@gmail.com'], msg.as_string())
except smtplib.SMTPAuthenticationError:
    print('Login failed: password or username invalid!')
finally:
    server.quit()

