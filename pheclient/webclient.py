#!/usr/bin/python3

import timeit
import requests
import json

from charm.core.engine.util import bytesToObject, objectToBytes
from charm.toolbox.ecgroup import ECGroup,ZR,G
from charm.toolbox.eccurve import prime256v1
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


group = ECGroup(prime256v1)

from .client import Client

class WebClient:

    def __init__(self, endpoint, requestobj):
        self._endpoint = endpoint
        self._requestobj = requestobj
        self.parameter()
        self._client = Client(self._generator, self._publickey)


    def parameter(self):
        response = self._requestobj.get("%s/parameter" % self._endpoint, verify = False)
        document = response.json()
        self._publickey = bytesToObject(document["X"], group)
        self._generator = bytesToObject(document["G"], group)


    def enrollment(self, pw):
        response = self._requestobj.get("%s/enroll" % self._endpoint, verify = False)
        document = response.json()
        c0    = bytesToObject(document["c0"],    group)
        c1    = bytesToObject(document["c1"],    group)
        ns    = bytesToObject(document["ns"],    group)
        proof = bytesToObject(document["proof"], group)

        return self._client.do_enrollment(pw, ns, (c0,c1), proof)


    def validation(self, pw, t, n):
        nc, ns = n

        c0 = self._client.get_validation(t, pw, nc)

        payload = {'c0': objectToBytes(c0, group),
                   'ns': objectToBytes(ns, group)}

        response = self._requestobj.get("%s/validate" % self._endpoint, params=payload, verify = False)
        document = response.json()

        return self._client.do_validation(t, pw, ns, nc,
                                          bytesToObject(document['c1'],    group),
                                          bytesToObject(document['proof'], group),
                                          document['result'])


    def rotation(self):
        response = self._requestobj.post("%s/rotate" % self._endpoint, verify = False)
        auxiliary = response.json()["alpha"], response.json()["beta"]
        self._client.do_rotation(auxiliary)

def read_dk(user,key):

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_enc = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key)
    )
    return private_enc

def write_byte(file, data):
    file = open(file, 'wb')
    file.write(data)  # The key is type bytes still
    file.close()

def read_byte(file):
    file = open(file, 'rb')
    data = file.read()  # The data will be type bytes
    file.close()
    return data

def read_n():
    n_bytes = read_byte('n')
    n = tuple(bytesToObject(n_bytes, group))
    return n

def read_t():
    t_bytes = read_byte('t')
    t = tuple(bytesToObject(t_bytes, group))
    return t

def read_m():
    m_bytes = read_byte('m')
    m = bytesToObject(m_bytes, group)
    return m


if __name__ == '__main__':
    import requests
    wc = WebClient("https://[fd00:638:a000:b101::2b75]/", requests)

    #m, t, n = wc.enrollment("s3kr1t")
    #print(m,t,n)
    #print(wc.validation("s3kr1t", t, n))

    m, t, n = wc.enrollment("Eleonora")

    n_bytes = objectToBytes(n, group)
    write_byte('n', n_bytes)
    t_bytes = objectToBytes(t, group)
    write_byte('t',t_bytes)
    m_bytes = objectToBytes(m, group)
    write_byte('m', m_bytes)
    m=None
    t=None
    n=None
    m=read_m()
    t=read_t()
    n=read_n()
    new_m=wc.validation("Eleonora",t,n)
    print(m)
    print(new_m)



