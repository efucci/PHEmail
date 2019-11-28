import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key,load_pem_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
from wkd import get_keys




def verify_sign(signature, message, user):
    # Load the public key.
    public_key = read_pk(user)

    try:
        public_key.verify(
            signature=signature,
            data=message.encode('utf-8'),
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
        is_correct = True

    except cryptography.InvalidSignature:
        is_correct = False

    return is_correct


#Decrypt
def decrypt_msg(encrypted, user):

    private_key = read_dk(user)
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



#Read public key (sign)
def read_pk(user):
    public_key = get_keys(user)
    public_key = load_pem_public_key(public_key.encode('utf-8'), default_backend())
    return public_key


#Read decrypt key
def read_dk(user):
    file = user+'/dk.key'
    with open(file, "rb") as key_file:
        private_key = load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


'''
message = 'ciao come stai'
enc1=encrypt_msg(message,'fuele95@gmail.com')

test1=base64.b64encode(enc1).decode('utf-8')
print('testo1 ', test1)

dec1=decrypt_msg(enc1,'fuele95@gmail.com')
print(dec1)
'''