import base64
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def encrypt(key, plaintext, associated_data):
    # Generate a random 96-bit IV.
    iv = os.urandom(16) #16 byte

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
    file = open(user+'/key.key', 'rb')
    key = file.read()  # The key will be type bytes
    file.close()

    return key

def store_key(user,password):
    key = os.urandom(32)
    file = open(user+'/key.key', 'wb')
    file.write(key)  # The key is type bytes still
    file.close()



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
def read_dk(user):
    file = user+'/dk.key'
    with open(file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
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


store_key('fuele95@gmail.com','oooo')
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


print("\ncipher key:\n",ciphertext)

dec_key=decrypt(
    key,
    b"authenticated but not encrypted payload",
    iv,
    ciphertext,
    tag
)





print("\ndecrypted_key\n",dec_key)

dec_key = load_pem_private_key(dec_key, password=None, backend=default_backend())

enc = encrypt_msg('ciao come stai?', 'fuele95@gmail.com' )

print("\nencrypt text\n",enc)

print("\ndecrypt text\n",decrypt_msg(enc,dec_key))


