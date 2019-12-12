#!/usr/bin/python3

import timeit
import requests
import json

from charm.core.engine.util import bytesToObject, objectToBytes
from charm.toolbox.ecgroup import ECGroup,ZR,G
from charm.toolbox.eccurve import prime256v1


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



