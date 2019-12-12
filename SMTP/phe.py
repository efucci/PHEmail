import os, requests
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.eccurve import prime256v1
from charm.toolbox.ecgroup import ECGroup
from pheclient.webclient import WebClient

group = ECGroup(prime256v1)


def read_byte(file):
    file = open(file, 'rb')
    data = file.read()  # The data will be type bytes
    file.close()
    return data

def read_n(user):
    n_bytes = read_byte(user+'/n')
    n = tuple(bytesToObject(n_bytes, group))
    return n

def read_t(user):
    t_bytes = read_byte(user+'/t')
    t = tuple(bytesToObject(t_bytes, group))
    return t

def retrieve_key(user, password):
    #   retrieve from PHE.py
    if not os.path.exists(user):
        raise ValueError('Error while retrieving key from phe. User not registred yet: ' + user)

    wc = WebClient("https://[fd00:638:a000:b101::2b75]/", requests)
    n = read_n(user)
    t = read_t(user)

    m = wc.validation(user+password, t , n)


    if m is not None:
        key = objectToBytes(m, group)
        print('key', key)
        return key
    else:
        #raise ValueError('Error while retrieving key from phe. Incorrect password or username: ' + user)
        m=read_byte(user+'/m')
        return m



'''
def read_private_key(user, password):
    try:
        if not os.path.exists(user):
            raise ValueError('Error while retrieving key from phe. User not registred yet: ' + user)
        ciphertext = read_byte(user + '/private_key.key')
        iv = read_byte(user + '/iv')
        tag = read_byte(user + '/tag')
        key = retrieve_key(user,password)
        plaintext = decrypt(key, iv, ciphertext, tag)
        private_key = load_pem_private_key(plaintext, password=None, backend=default_backend())
    except Exception as e:
        print(f'Error in read_private_key: {e}')
        raise ValueError(e)
    else:
        return private_key
'''



