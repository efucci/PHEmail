import os

import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
from IMAP import phe, wkd


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
def decrypt_msg(encrypted, private_key):
    try:
        #private_key = read_dk(user, password)
        original_message = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f'During encryption an error occurred: {e}')
    else:
        return base64.b64decode(original_message).decode('utf-8')


#Read public key (sign)
def read_pk(user):
    try:
        public_key = wkd.get_key(user)
        public_key = load_pem_public_key(public_key.encode('utf-8'), default_backend())
        return public_key
    except Exception:
        raise ValueError('ERROR: public key of ' + user + ' failed! Signature verification is not possible')


#Read private key (sign - secret key)
def read_dk(user,password):
    if not os.path.exists(user):
        raise ValueError('Error while retrieving key from phe. User not registred yet: IMAP/' + user)
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
