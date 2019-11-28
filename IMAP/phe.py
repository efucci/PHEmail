import base64
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from registration import read_dk
from wkd import get_keys


def encrypt(key, plaintext, associated_data):
    # Generate a random 96-bit IV.
    iv = os.urandom(12) #12 byte

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)

def decrypt(key, associated_data, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()

#The key is given by PHE.py, we need username, password and the text to encrypt (private key or decryption key)

def retrieve_key(user, password):
    #richiesta al PHE.py
    print(user,password)
    key = os.urandom(32)
    return key

#Read private key (sign)
def read_sk(user):
    file = user+'/sk.key'
    with open(file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    return private_key

def encrypt_msg(message, user, public_key):

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

def read_ek(user):
    encrypt_key = get_keys(user,'encrypt_key')
    #encrypt_key = load_pem_public_key(encrypt_key.encode('utf-8'),default_backend())
    return encrypt_key.encode('utf-8')

#key = os.urandom(32)
key=retrieve_key("user","test")
#plain = b"a secret message!"
plain = read_ek('author@example.com')
print("key in plain\n: ",plain)

iv, ciphertext, tag = encrypt(
    key,
    plain,
    b"authenticated but not encrypted payload"
)


print("\ncipher key:\n",ciphertext)

dec=decrypt(
    key,
    b"authenticated but not encrypted payload",
    iv,
    ciphertext,
    tag
)


print("\ndecrypted_key\n",dec)

encrypt_key = load_pem_public_key(dec,default_backend())

enc=encrypt_msg('ciao come stai?', 'user', encrypt_key)

print("\nencrypt text\n",enc)

print("\ndecrypt text\n",decrypt_msg(enc,'author@example.com'))


