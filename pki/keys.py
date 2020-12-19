from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, ed25519, ec as ecc
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import exceptions as cryptography_exceptions

from asn1crypto import algos, core as asn1
from pymrtd.pki import algo_utils, iso9796e2, oids
from typing import Optional


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
    _fields  = [
        ('algorithm', SignatureAlgorithmId),
        *algos.SignedDigestAlgorithm._fields[1:]
    ]

    @property
    def isPlain(self) -> bool:
        return 'plain' in self['algorithm'].native

    @property
    def signatureAlgo(self) -> str:
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
    def hashAlgo(self) -> str:
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


class ECDSA_X962_Sig(asn1.Sequence):
    ''' Represents X9.64 ECDSA signature format '''

    _fields = [
        ("r", asn1.Integer),
        ("s", asn1.Integer)
    ]

    @classmethod
    def fromPlain(cls, plainSig: bytes):
        ''' Constructs cls object from plain raw signature (r||s) '''

        if len(plainSig) % 2 != 0:
            raise ValueError("Cannot convert signature to X9.62 format, signature not even length.")
        l = int(len(plainSig) / 2)
        r = int.from_bytes(plainSig[:l], byteorder='big', signed=True)
        s = int.from_bytes(plainSig[l:], byteorder='big', signed=True)
        return cls({"r": r, "s": s})

    def toPlain(self) -> bytes:
        # TODO: use i2osp of pkcs#1 to encode each integers
        r = self['r'].contents
        s = self['s'].contents
        lr = len(r)
        ls = len(s)
        if (lr + ls) % 2 != 0:
            if lr < ls:
                r = b'\x00' * int(ls - lr) + r
            else:
                s = b'\x00' * int(lr - ls) + s
        return r + s

class PublicKey:
    ''' General abstract class which represents public key for PKI '''

    _pub_key = None

    @classmethod
    def load(cls, der_encoded_key: bytes):
        key = cls()
        key._pub_key = serialization.load_der_public_key(
            der_encoded_key, default_backend()
        )
        return key

    def dump(self):
        return self._pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def isDsaKey(self) -> bool:
        return isinstance(self._pub_key, dsa.DSAPublicKey)

    def isEcKey(self) ->bool:
        return isinstance(self._pub_key, ecc.EllipticCurvePublicKey)

    def isEdKey(self) ->bool:
        return isinstance(self._pub_key, ed25519.Ed25519PublicKey)

    def isRsaKey(self) -> bool:
        return isinstance(self._pub_key, rsa.RSAPublicKey)

    def verifySignature(self, message: bytes, signature: bytes, sigAlgo: SignatureAlgorithm) -> bool:
        """
        Verifies digital signature made over message against public key.
        :param message: Message to verify signature against
        :param signature: Raw signature bytes.
                          ECDSA signature can be bytes of x9.62 format or plain format (R||S).
        :param sigAlgo: Signature algorithm used to produce signature.
        :return: True if signature is valid, otherwise False
        :raises:  *Exception - if other then InvalidSignature exception is risen.
        """

        # Convert parent type algos.SignedDigestAlgorithm to SignatureAlgorithm
        if not isinstance(sigAlgo, SignatureAlgorithm):
            sigAlgo.__class__ = SignatureAlgorithm

        # Convert plain ECDSA sig to x9.62 format
        if sigAlgo.isPlain:
            signature = ECDSA_X962_Sig.fromPlain(signature).dump()

        hash_algo = algo_utils.get_hash_algo_by_name(sigAlgo.hashAlgo)

        class Verifier:
            def __init__(self, vf):
                self._vf = vf
            def verify(self):
                return self._vf()

        def get_rsa_verifier(pub_key: rsa.RSAPublicKey):
            if sigAlgo.signature_algo == 'rsassa_pss':
                sig_algo_params = sigAlgo['parameters']
                assert 'mask_gen_algorithm' in sig_algo_params
                assert 'salt_length' in sig_algo_params

                mgf = sig_algo_params['mask_gen_algorithm']['algorithm'].native
                if 'mgf1' != mgf:
                    raise ValueError("Invalid mask generation algorithm: {}".format(mgf))

                mgf1_hash_algo = sig_algo_params['mask_gen_algorithm']['parameters']['algorithm'].native
                mgf1_hash_algo = algo_utils.get_hash_algo_by_name(mgf1_hash_algo)
                return Verifier(lambda:
                    pub_key.verify(
                        signature,
                        message,
                        padding.PSS(
                            mgf = padding.MGF1(mgf1_hash_algo),
                            salt_length = sig_algo_params['salt_length'].native
                        ),
                        hash_algo
                ))
            else:
                return Verifier(lambda:
                    pub_key.verify(signature, message, padding.PKCS1v15(), hash_algo)
                )

        def get_ecdsa_verifier(pub_key: ecc.EllipticCurvePublicKey):
            return Verifier(lambda:
                pub_key.verify(signature, message, ecc.ECDSA(hash_algo))
            )

        def get_eddsa_verifier(pub_key: ed25519.Ed25519PublicKey):
            return Verifier(lambda:
                pub_key.verify(signature, message)
            )

        def get_dsa_verifier(pub_key: ecc.EllipticCurvePublicKey):
            return Verifier(lambda:
                pub_key.verify(signature, message, hash_algo)
            )

        # Get signature verifier
        if self.isRsaKey():
            verifier = get_rsa_verifier(self._pub_key)
        elif self.isEcKey():
            verifier = get_ecdsa_verifier(self._pub_key)
        elif self.isEdKey():
            verifier = get_eddsa_verifier(self._pub_key)
        else:
            verifier = get_dsa_verifier(self._pub_key)

        # Verify sig
        try:
            verifier.verify()
        except cryptography_exceptions.InvalidSignature:
            return False
        return True


class AAPublicKey(PublicKey):
    '''' Represents eMRTD Active Authentication public key '''

    def verifySignature(self, message: bytes, signature: bytes, sigAlgo: Optional[SignatureAlgorithm] = None) -> bool:
        """
        Verifies if signature is valid using AA public key.
        :param message: Message to verify signature against
        :param signature:
        :param sigAlgo: Signature algorithm used to produce signature. (ECC only)
        :return: True if signature is valid, otherwise False
        """

        if self.isRsaKey():
            v = iso9796e2.Dss1Verifier(self._pub_key)
            return v.verifySignature(message, signature)
        elif self.isEcKey():
            # WARNING: THIS SCOPE WAS TESTED WITH ECDSA SIGNATURE NOT FROM eMRTD IC
            if sigAlgo is None:
                raise ValueError("Missing required param 'sigAlgo'")
            return super().verifySignature(message, signature, sigAlgo)
        else:
            raise ValueError("Unsupported digital signature scheme")

# Monkey patch _EllipticCurvePublicKey to allow unnamed curves (explicit params)
from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePublicKey,
    _mark_asn1_named_ec_curve,
    _ec_key_curve_sn,
    _sn_to_elliptic_curve
)

def _new_ec_pub_key_init(self, backend, ec_key_cdata, evp_pkey):
    self._backend = backend
    self._ec_key = ec_key_cdata
    self._evp_pkey = evp_pkey
    try:
        _mark_asn1_named_ec_curve(backend, ec_key_cdata)
        sn = _ec_key_curve_sn(backend, ec_key_cdata)
        self._curve = _sn_to_elliptic_curve(backend, sn)
    except:
        self._curve = None

_EllipticCurvePublicKey.__init__ = _new_ec_pub_key_init