"""
    Implementation of the PyCIRCLeanMail module.
    Sanitize emails before being fetched by the user.
"""
import base64
import email, re, imaplib, time
#from .helpers import parse_ids
from IMAP.crypto_utils import decrypt_msg, verify_sign

Fetch = re.compile(r'(?P<tag>[A-Z0-9]+)'
    r'(\s(UID))?'
    r'\s(FETCH)'
    r'\s(?P<ids>[0-9:,]+)'
    r'\s(?P<flags>.*)', flags=re.IGNORECASE)

CRLF = b'\r\n'

# Default Quarantine folder
#QUARANTINE_FOLDER = 'Quarantine'

# Sanitizer header and values
#CIRCL_SIGN = 'X-CIRCL-Sanitizer'
SIGN_VERIFICATION = 'PHE-Proxy-Sign'
VALUE_ORIGINAL = 'Original'
#VALUE_SANITIZED= 'Sanitized'
#VALUE_ERROR= 'Error'
VALUE_DECRYPTED = 'PHE-proxy-Decryption'
# Proxy header to verify email integrity
PROXY_SIGN = 'X-Proxy-Sign'

# Message data used to get the flags and sanitizer header
#MSG_DATA_FS = '(FLAGS BODY.PEEK[HEADER.FIELDS (' + CIRCL_SIGN + ')])'
# Message data used to get the entire mail
MSG_DATA = 'BODY.PEEK[]'
#MSG_DATA = '(RFC822)'

def process(client):
    """

        client - Connection object

    """
    conn_client = client.conn_client
    request = client.request
    conn_server = client.conn_server
    folder = client.current_folder
    private_key = client.private_key
    print('Sono in processs')

    uidc = True if (('UID' in request) or ('uid' in request)) else False

    match = Fetch.match(request)

    if not match:
        print('return ++++++++++++++++ 2')
        return # Client discovers new emails (presence of '*' key)
    ids = match.group('ids')

    if ids.isdigit():
        data=process_email(ids, conn_server, conn_client, folder, uidc, private_key)
        if data == None:
            return
        else:
            return data
    else:
        return
        # Multiple emails are fetched (ids format: [0-9,:])
        #for id in parse_ids(ids):
        #    print('multiple')
        #    process_email(str(id), conn_server, conn_client,folder, uidc, private_key)

def process_email(id, conn_server, conn_client, folder, uidc, key):
    """ Decrypt email and verify sign, if possible.

        id - String containing the id of the email to fetch;
        conn_server - imaplib connection to the server;
        folder - Current folder of the client;
        uidc - True if command contains UID flag
        key - key used to verify integrity of email
    """
    conn_server.select(folder)

    #   -- No signature or incorrect value --

    bmail, decrypt_value, verify_sign_value = fetch_entire_email(id, conn_server, uidc, key)
    #print(bmail)
    if not bmail:
        print('return ++++++++++++++++ 3 ')
        return

    mail = email.message_from_string(bmail)

    # Get the DATE of the email
    date_str = mail.get('Date')
    date = imaplib.Internaldate2tuple(date_str.encode()) if date_str else imaplib.Time2Internaldate(time.time())

    # Append decrytped message
    if decrypt_value == 'Decryption successful':
        mail=append_email(conn_server, mail, decrypt_value, verify_sign_value, date, folder, conn_client)
        #conn_server.uid('STORE', id, '+FLAGS', '(\Deleted)') if uidc else conn_server.store(id, '+FLAGS', '(\Deleted)')
        return mail
    else:
        return
    #Send messge to clien
    #for item in mail:
    #    conn_client.send(item)
    #    data = conn_client.recv(1024)
    #    print('Client received: ', data)


    # Delete original
    #conn_server.uid('STORE', id, '+FLAGS', '(\Deleted)') if uidc else conn_server.store(id, '+FLAGS', '(\Deleted)')

    #conn_server.expunge()



def fetch_entire_email(id, conn_server, uidc, private_key):
    """ Return the raw_email in bytes """
    if uidc and id is not None:
    #result, response = conn_server.uid('fetch', id, MSG_DATA) if uidc else conn_server.fetch(id, MSG_DATA)
        result, response = conn_server.uid('fetch', id, '(RFC822)')
    else:
        return
    decrypt_value = 'Decryption failed'
    verify_sign_value = 'No signature'

    if result == 'OK' and response != [b'The specified message set is invalid.'] and response != [None]:
        email_message = email.message_from_bytes(response[0][1])
        print('sono qui 1')
        try:
            v=email_message.get(VALUE_DECRYPTED)
            if v != None:
                print('email already fetched!')
                return False, None, None
        except Exception as e :
            print(e)
        try:
            print('sono qui 2')
            pay = base64.b64decode(get_payload(email_message))
            dec = decrypt_msg(pay, private_key)
            email_message.set_payload(dec)

            try:
                print('sono qui 3')

                sign = base64.b64decode(email_message['Signature'])
                sender =  get_sender(email_message['From'])
                print('sono qui 5')
                verified = verify_sign(sign, dec,sender)
                verify_sign_value= 'Verification successful' if verified else 'Verification failed'
            except Exception as e:
                print('sign error', e)
                return email_message.as_string(), decrypt_value, verify_sign_value

        except Exception as e:
            print('dec error', e)

            return email_message.as_string(), decrypt_value, verify_sign_value
        else:
            decrypt_value = 'Decryption successful'
            return email_message.as_string(), decrypt_value, verify_sign_value
    else:
        return




def append_email(conn_server, mail, decrypted_value, sign_value, date, folder, conn_client):
    """ Append the email on the server """
    mail.add_header(VALUE_DECRYPTED, decrypted_value)
    mail.add_header(SIGN_VERIFICATION, sign_value)
    print('email : \n',mail)
    #conn_server.append(folder, '', date, str(mail).encode())
    #send_to_client(conn_client, mail.as_string())
    return mail

def get_payload(mail):
    """ Return the payload of the given email """
    res = ''
    if mail.is_multipart():
        for payload in mail.get_payload():
            res += payload.get_payload()
    else:
        res = mail.get_payload()

    return res

def get_sender(user):
    print('sono qui 4')

    r = re.search(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", user)
    if(r):
        return r[0]
    else:
        return r


def parse_ids(str_ids):
    """ Convert string of ids to a list of ids

        str_ids - ids of format "1:6" or "1,3:5" or "1,4"

    If str_ids = "1:6", return (1,2,3,4,5,6).
    If str_ids = "1,3:5", return (1,3,4,5).
    If str_ids = "1,4", return (1,4).
    """

    ids = []
    raw_ids = str_ids.split(',')

    for s in raw_ids:
        if ':' in s:
            (start, end) = s.split(':')
            print(start, end)
            [ids.append(i) for i in range(int(start), int(end)+1)]
        else:
            ids.append(int(s))

    return ids

def send_to_client(conn_client, str_data):
    """ Send String data (without CRLF) to the client """
    b_data = str_data.encode('utf-8', 'replace') + CRLF
    conn_client.send(b_data)


