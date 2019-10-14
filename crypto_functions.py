import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64



#Generate pair key
def gen_keys(user):
    decrypt_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    encrypt_key = decrypt_key.public_key()

    store_dk(decrypt_key,user)
    store_ek(encrypt_key,user)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    store_sk(private_key, user)
    store_pk(public_key, user)



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



#Encrypt
def encrypt_msg(message, user):

    public_key=read_ek(user)
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
    private_key=read_dk(user)

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



#Store encrypt key
def store_ek(public_key, user):

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    file = user + '/ek.pem'
    with open(file, 'wb') as f:
        f.write(pem)


#Store decrypt key
def store_dk(private_key, user):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    file = user + '/dk.key'
    with open(file, 'wb') as f:
        f.write(pem)


#Store public key (sign)
def store_pk(public_key, user):

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    file = user + '/pk.pem'
    with open(file, 'wb') as f:
        f.write(pem)


#Store private key (sign)
def store_sk(private_key, user):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    file = user + '/sk.key'
    with open(file, 'wb') as f:
        f.write(pem)



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

#Read public key (sign)
def read_pk(user):
    file = user+'/pk.pem'
    with open(file, 'rb') as pem_in:
        pemlines = pem_in.read()
    public_key = load_pem_public_key(pemlines, default_backend())

    return public_key


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



