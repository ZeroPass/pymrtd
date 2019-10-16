from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec as ecc
import pymrtd.pki.iso9796e2 as iso9796e2


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