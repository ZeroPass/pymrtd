from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec as ecc

from pymrtd.pki import iso9796e2, oids

from asn1crypto import algos

class SignatureAlgorithmId(algos.SignedDigestAlgorithmId):
    _map = dict(algos.SignedDigestAlgorithmId._map, **{
        oids.ecdsa_plain_SHA1   : 'sha1_plain_ecdsa',
        oids.ecdsa_plain_SHA224 : 'sha224_plain_ecdsa',
        oids.ecdsa_plain_SHA256 : 'sha256_plain_ecdsa',
        oids.ecdsa_plain_SHA384 : 'sha384_plain_ecdsa',
        oids.ecdsa_plain_SHA512 : 'sha512_plain_ecdsa'
    })

    _reverse_map = dict(algos.SignedDigestAlgorithmId._reverse_map, **{
        'sha1_plain_ecdsa'   : oids.ecdsa_plain_SHA1,
        'sha224_plain_ecdsa' : oids.ecdsa_plain_SHA224,
        'sha256_plain_ecdsa' : oids.ecdsa_plain_SHA256,
        'sha384_plain_ecdsa' : oids.ecdsa_plain_SHA384,
        'sha512_plain_ecdsa' : oids.ecdsa_plain_SHA512
    })


class SignatureAlgorithm(algos.SignedDigestAlgorithm):
    _fields  = [('algorithm', SignatureAlgorithmId), *algos.SignedDigestAlgorithm._fields[1:]]

    @property
    def isPlain(self):
        return 'plain' in self['algorithm'].native

    @property
    def signatureAlgo(self):
        if not self.isPlain:
            return super().signature_algo

        algorithm = self['algorithm'].native
        algo_map = {
            'sha1_plain_ecdsa': 'ecdsa',
            'sha224_plain_ecdsa': 'ecdsa',
            'sha256_plain_ecdsa': 'ecdsa',
            'sha384_plain_ecdsa': 'ecdsa',
            'sha512_plain_ecdsa': 'ecdsa'
        }

        if algorithm in algo_map:
            return algo_map[algorithm]
        raise ValueError('Signature algorithm not known for '.format(algorithm))

    @property
    def hashAlgo(self):
        if not self.isPlain:
            return super().hash_algo

        algorithm = self['algorithm'].native
        algo_map = {
            'sha1_plain_ecdsa': 'sha1',
            'sha224_plain_ecdsa': 'sha224',
            'sha256_plain_ecdsa': 'sha256',
            'sha384_plain_ecdsa': 'sha384',
            'sha512_plain_ecdsa': 'sha512',
        }

        if algorithm in algo_map:
            return algo_map[algorithm]
        raise ValueError('Hash algorithm not known for '.format(algorithm))


class AAPublicKey:
    _pub_key = None

    @classmethod
    def load(cls, der_encoded_key: bytes):
        key = AAPublicKey()
        key._pub_key = serialization.load_der_public_key(
            der_encoded_key, default_backend()
        )
        return key

    def isEcc(self):
        return isinstance(self._pub_key, ecc.EllipticCurvePublicKey)

    def isRsa(self):
        isinstance(self._pub_key, rsa.RSAPublicKey)

    def dump(self):
        return self._pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def verifySignature(self, message: bytes, signature: bytes) -> bool:
        """
        Verifies if signature is valid using AA public key.
        :param message: Message to verify signature against
        :param signature:
        :return: True if signature is valid, otherwise False
        """

        if isinstance(self._pub_key, rsa.RSAPublicKey):
            v = iso9796e2.Dss1Verifier(self._pub_key)
            return v.verifySignature(message, signature)
        else:
            raise NotImplementedError("ECDSA is not implemented yet")