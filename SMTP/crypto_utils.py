import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key,load_pem_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
from wkd import get_keys



def sign_msg(message, user):

    # Load the private key.
    private_key = read_sk(user)

    signature = private_key.sign(
        data=message.encode('utf-8'),
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256()
    )

    return signature


#Encrypt
def encrypt_msg(message, user):

    public_key = read_ek(user)
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


#Read private key (sign)
def read_sk(user):
    file = user+'/sk.key'
    with open(file, "rb") as key_file:
        private_key = load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


#Read encrypt key
def read_ek(user):
    encrypt_key = get_keys(user)
    encrypt_key = load_pem_public_key(encrypt_key.encode('utf-8'),default_backend())
    return encrypt_key




'''
message = 'ciao come stai'
enc1=encrypt_msg(message,'fuele95@gmail.com')

test1=base64.b64encode(enc1).decode('utf-8')
print('testo1 ', test1)

dec1=decrypt_msg(enc1,'fuele95@gmail.com')
print(dec1)
'''