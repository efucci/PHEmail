import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os, requests
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.eccurve import prime256v1
from charm.toolbox.ecgroup import ECGroup
from pheclient.webclient import WebClient

group = ECGroup(prime256v1)


#The key is given by PHE.py, we need username, password and the text to encrypt (private key or decryption key)

def read_byte(file):
    file = open(file, 'rb')
    data = file.read()  # The data will be type bytes
    file.close()
    return data

def write_byte(file, data):
    file = open(file, 'wb')
    file.write(data)  # The key is type bytes still
    file.close()


def write_object(file,obj):
    o_bytes = objectToBytes(obj,group)
    write_byte(file, o_bytes)



def store_private_keys(decrypt_key, secret_key, user, password):

    wc = WebClient("https://[fd00:638:a000:b101::2b75]/", requests)
    m, t, n = wc.enrollment(user+password)  #phe-registration
    m_bytes = objectToBytes(m, group)

    decrypt_key = decrypt_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(m_bytes)
    )
    secret_key = secret_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(m_bytes)
    )


    if not os.path.exists(user):
        os.mkdir(user)
    write_byte(user+'/m', m_bytes)

    imap_path = 'IMAP/'+user
    if not os.path.exists(imap_path):
        os.mkdir(imap_path)
    write_byte(imap_path+'/private_key.key', decrypt_key)
    write_object(imap_path + '/n', n)
    write_object(imap_path + '/t', t)
    write_byte(imap_path + '/m', m_bytes)

    smtp_path = 'SMTP/'+user
    if not os.path.exists(smtp_path):
        os.mkdir(smtp_path)
    write_byte(smtp_path + '/private_key.key', secret_key)
    write_object(smtp_path + '/n', n)
    write_object(smtp_path + '/t', t)
    write_byte(smtp_path + '/m', m_bytes)


'''

def read_private_key(user, password):

    if not os.path.exists(user):
        raise ValueError('Error while retrieving key from phe. User not registred yet: SMTP/' + user)
    #ciphertext = read_byte('IMAP/'+user+'/private_key.key')
    #iv = read_byte('IMAP/'+user + '/iv')
    #tag = read_byte('IMAP/'+user +'/tag')
    key = retrieve_key(user,password)
    private_key= read_dk(user,key)
    #plaintext = decrypt(key,iv, ciphertext, tag)
    #private_key = load_pem_private_key(plaintext, password=None, backend=default_backend())

    return private_key


def encrypt_msg(message, public_key):

    #public_key = read_ek(user)
    message = base64.b64encode(message.encode('utf-8'))
    #message=bytes(message,'utf-8')
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


#Decrypt
def decrypt_msg(encrypted, private_key):
    #private_key = read_dk(user)
    #encrypted=bytes(encrypted,"utf-8")
    original_message = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64decode(original_message).decode('utf-8')


#Read decrypt key
def read_dk(user,key):
    file = user+'/private_key.key'
    with open(file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=key,
            backend=default_backend()
        )
    return private_key


#Read encrypt key
def read_ek(user):

    file = user+'/ek.pem'
    with open(file, 'rb') as pem_in:
        pemlines = pem_in.read()
    public_key = load_pem_public_key(pemlines, default_backend())

    return public_key


decrypt_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
print(decrypt_key)
key=os.urandom(16)
encrypt_key = decrypt_key.public_key()
store_private_key(key, decrypt_key, 'test','ciao',type='decrypt')
message = 'ciao, come stai?'
cip = encrypt_msg(message, encrypt_key)
new_encrypt_key = read_private_key('test','ciao')
print(new_encrypt_key)
plain = decrypt_msg(cip,new_encrypt_key)
print(plain)


#store_key('fuele95@gmail.com','oooo')
key=retrieve_key('fuele95@gmail.com','oooo')

private_key = read_dk('fuele95@gmail.com')
plaintext =  private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

public_key = read_ek('fuele95@gmail.com')

print("key in plain\n: ", plaintext)

iv, ciphertext, tag = encrypt(
    key,
    plaintext,
    b"authenticated but not encrypted payload"
)

print(ciphertext)
file = open('test/private_key.key', 'wb')
file.write(ciphertext)  # The key is type bytes still
file.close()


file = open('test/private_key.key', 'rb')
private_byte = file.read()
file.close()
print(private_byte)
dec_key=decrypt(
    key,
    b"authenticated but not encrypted payload",
    iv,
    private_byte,
    tag
)



print("\ndecrypted_key\n",dec_key)

dec_key = load_pem_private_key(dec_key, password=None, backend=default_backend())

enc = encrypt_msg('ciao come stai?', 'fuele95@gmail.com' )

print("\nencrypt text\n",enc)

print("\ndecrypt text\n",decrypt_msg(enc,dec_key))

'''