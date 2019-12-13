from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from wkd import put_keys
from cryptography.hazmat.primitives import serialization
import PHE, getpass
import os




#Generate pair key
def gen_keys(fullname, user, password):
    try:
        decrypt_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        encrypt_key = decrypt_key.public_key()
        encrypt_pem = encrypt_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        PHE.store_private_keys(decrypt_key, private_key, user, password)
        put_keys(user, fullname, public_pem, encrypt_pem)

    except Exception as e:
        raise ValueError(f'An error occurred: {e}')


def store_dk(key, private_key,user, password):
    PHE.store_private_keys(key,private_key, user, password,'decrypt')

def store_sk(key,private_key, user, password):
    PHE.store_private_key(key,private_key, user, password,'private')



fullname = input("Your fullname: ")
user = input("Your username: ")
#password = input("Your password: ")

password = getpass.getpass("PASSWORD: ")


try:
    gen_keys(fullname, user, password)
except Exception as e:
    print(e)
else:
    print('Registration completed!')
