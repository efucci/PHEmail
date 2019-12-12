"""This module implements the Pedila client."""

from charm.toolbox.ecgroup import ECGroup,ZR,G
from charm.toolbox.eccurve import prime256v1
from charm.core.engine.util import bytesToObject, objectToBytes

import os
import os.path

group = ECGroup(prime256v1)

class Client():
    """The Pedila client implementation. Inputs are usually JSON encoded."""
    def __init__(self, generator, public_key):
        """Expects CHARM group elements @generator and @public_key. Initializes
           an empty update token."""

        self.G = generator
        self.X = public_key

        if os.path.exists('key.b64'):
            with open('key.b64', 'rb') as keyfile:
                self.y = bytesToObject(keyfile.read(), group)
        else:
            self.y = group.random(ZR)
            with open('key.b64', 'wb') as keyfile:
                keyfile.write(objectToBytes(self.y, group))


    def do_rotation(self, a1, a2, b1, b2, g, phi):
        alpha, _ = auxiliary
        self._prf_key = self._prf_key * alpha
        for record in []:
            newrecord = self.update_record(record, auxiliary)


    def do_enrollment(self, pw, ns, c, proof):
        """Generate enrollment record from server data"""
        c0, c1 = c
        term1, term2, term3, blind_x = proof

        nc = group.random(ZR)

        hc0 = group.hash((nc, pw, b'0'), target_type=G)
        hc1 = group.hash((nc, pw, b'1'), target_type=G)

        hs0 = group.hash((ns, b'0'), target_type=G)
        hs1 = group.hash((ns, b'1'), target_type=G)

        m = group.random(G)

        def validate_proof():
            challenge = group.hash((self.X, self.G, c0, c1, term1, term2, term3), target_type=ZR)

            if term1 * (c0 ** challenge) != hs0 ** blind_x:
                return False
            if term2 * (c1 ** challenge) != hs1 ** blind_x:
                return False
            if term3 * (self.X ** challenge) != self.G ** blind_x:
                return False

            return True

        if validate_proof() == False:
            print("EXCEPTION")
            return

        t0 = c0 * (hc0 ** self.y)
        t1 = c1 * (hc1 ** self.y) * (m ** self.y)
        return m, (t0, t1), (nc, ns)


    def get_validation(self, t, pw, nc):
        """Generate validation request data"""
        t0, t1 = t

        hc0 = group.hash((nc, pw, b'0'), target_type=G)
        c0 = t0 * (hc0 ** (-self.y))

        return c0


    def do_validation(self, t, pw, ns, nc, c1, proof, result):
        """Interpret validation result"""
        t0, t1 = t

        hc0 = group.hash((nc, pw, b'0'), target_type=G)
        hc1 = group.hash((nc, pw, b'1'), target_type=G)

        hs0 = group.hash((ns, b'0'), target_type=G)
        hs1 = group.hash((ns, b'1'), target_type=G)
        
        c0 = t0 * (hc0 ** (-self.y))

        if result == True:
            def validate_proof():
                term1, term2, term3, blind_x = proof
                challenge = group.hash((self.X, self.G, c0, c1, term1, term2, term3), target_type=ZR)

                if term1 * (c0 ** challenge) != hs0 ** blind_x:
                    return False
                if term2 * (c1 ** challenge) != hs1 ** blind_x:
                    return False
                if term3 * (self.X ** challenge) != self.G ** blind_x:
                    return False

                return True

            if not validate_proof():
                print("EXCEPTION")
                return

            return ((t1 * (c1 ** (-1))) * (hc1 ** (-self.y))) ** (self.y ** (-1))

        else:
            def validate_proof():
                term1, term2, term3, term4, I, blind_a, blind_b = proof
                challenge = group.hash((self.X, self.G, c0, c1, term1, term2, term3, term4), target_type=ZR)

                if term1 * term2 * (c1 ** challenge) != (c0 ** blind_a) * (hs0 ** blind_b):
                    return False

                if term3 * term4 * (I ** challenge) != (self.X ** blind_a) * (self.G ** blind_b):
                    return False

                return True

            if not validate_proof():
                print("EXCEPTION")
                return

            return None


    def update_record(self, record, update_token):
        """Applies the @update_token to a stored enrollment @record. Returns the updated
           record."""
        T1, T2, T3 = record
        h, z = self._public_key
        alpha, beta = update_token
        rerandom = group.random(ZR)

        return (T1 * (self._generator ** rerandom),
                (T2 * h ** rerandom) ** alpha,
                (t3 * z ** rerandom) ** (alpha * beta))
