from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from wkd import put_keys



#Generate pair key
def gen_keys(fullname, user, password):
    decrypt_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    encrypt_key = decrypt_key.public_key()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    store_dk(decrypt_key, user)
    store_sk(private_key, user)
    put_keys(user, fullname, public_key, encrypt_key)


#Store decrypt key
def store_dk(private_key, user):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    file = 'IMAP' +user + '/dk.key'
    with open(file, 'wb') as f:
        f.write(pem)


#Store private key (sign)
def store_sk(private_key, user):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    file = 'SMTP' + user + '/sk.key'
    with open(file, 'wb') as f:
        f.write(pem)




'''
message = 'ciao come stai'
enc1=encrypt_msg(message,'fuele95@gmail.com')

test1=base64.b64encode(enc1).decode('utf-8')
print('testo1 ', test1)

dec1=decrypt_msg(enc1,'fuele95@gmail.com')
print(dec1)
'''

fullname = input("Your fullname: ")
user = input("Your username: ")
password = input("Your password: ")

try:
    gen_keys(fullname, user, password)
except Exception as e:
    print(e)
else:
    print('Registration completed!')