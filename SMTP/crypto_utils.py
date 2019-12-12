import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key,load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
from SMTP import phe, wkd



def sign_msg(message, user, password):
    # Load the private key.
    try:
        private_key = read_sk(user, password)
        signature = private_key.sign(
        data=message.encode('utf-8'),
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256()
    )
    except Exception as e:
        raise ValueError(e)
        print(e)
    else:
        return signature


#Encrypt
def encrypt_msg(message, user):
    try:
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
    except Exception as e:
        raise ValueError(f'During encryption an error occurred: {e}')


#Read private key (sign - secret key)
def read_sk(user, password):
    if not os.path.exists(user):
        raise ValueError('Error while retrieving key from phe. User not registred yet: SMTP/' + user)
    try:
        key = phe.retrieve_key(user, password)
        with open(user + '/private_key.key', "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=key,
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(e)
    else:
        return private_key

#Read encrypt key
def read_ek(user):
    try:
        encrypt_key = wkd.get_key(user)
        encrypt_key = load_pem_public_key(encrypt_key.encode('utf-8'),default_backend())
        return encrypt_key
    except Exception:
        raise ValueError('ERROR: public key of '+user+' failed! Email encryption is not possible')



'''
message = 'ciao come stai'
enc1=encrypt_msg(message,'fuele95@gmail.com')

test1=base64.b64encode(enc1).decode('utf-8')
print('testo1 ', test1)

#dec1=decrypt_msg(enc1,'fuele95@gmail.com')
#print(dec1)
'''