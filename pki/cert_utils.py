from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec as ecc
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography import exceptions as cryptography_exceptions

from asn1crypto import x509


_STR_TO_HASH_ALGO = {
    'md5': hashes.MD5(),
    'sha1': hashes.SHA1(),
    'sha224': hashes.SHA224(),
    'sha256': hashes.SHA256(),
    'sha384': hashes.SHA384(),
    'sha512': hashes.SHA512(),
}

def verify_cert_sig(issued_cert: x509.Certificate, issuing_cert: x509.Certificate) -> bool:
    """
    Verifies digital signature of issued certificate against issuing certificate's public key.
    It returns True if verification succeeds, otherwise False.
    """

    class Verifier:
        def __init__(self, vf):
            self._vf = vf
        def verify(self):
            return self._vf()

    def get_rsa_verifier(pub_key: rsa.RSAPublicKey, tbs_cert: x509.TbsCertificate, sig_bytes: bytes):
        sig_algo  = tbs_cert['signature']
        hash_algo = _STR_TO_HASH_ALGO[sig_algo.hash_algo]
        if sig_algo.signature_algo == 'rsassa_pss':
            sig_algo_params = sig_algo['parameters']
            assert 'mask_gen_algorithm' in sig_algo_params
            assert 'salt_length' in sig_algo_params

            mgf = sig_algo_params['mask_gen_algorithm']['algorithm'].native
            if 'mgf1' != mgf:
                raise ValueError("Invalid mask generation algorithm: {}".format(mgf))

            mgf1_hash_algo = sig_algo_params['mask_gen_algorithm']['parameters']['algorithm'].native
            mgf1_hash_algo = _STR_TO_HASH_ALGO[mgf1_hash_algo]
            return Verifier(lambda: 
                pub_key.verify(
                    sig_bytes,
                    tbs_cert.dump(),
                    padding.PSS(
                        mgf = padding.MGF1(mgf1_hash_algo),
                        salt_length = sig_algo_params['salt_length'].native
                    ),
                    hash_algo
            ))
        else:
            return Verifier(lambda: 
                pub_key.verify(sig_bytes, tbs_cert.dump(), padding.PKCS1v15(), hash_algo)
            )

    def get_ecdsa_verifier(pub_key: ecc.EllipticCurvePublicKey, tbs_cert: x509.TbsCertificate, sig_bytes: bytes):
        sig_algo  = tbs_cert['signature']
        hash_algo = _STR_TO_HASH_ALGO[sig_algo.hash_algo]
        return Verifier(lambda: 
            pub_key.verify(sig_bytes, tbs_cert.dump(), ecc.ECDSA(hash_algo))
        )

    def get_eddsa_verifier(pub_key: ed25519.Ed25519PublicKey, tbs_cert: x509.TbsCertificate, sig_bytes: bytes):
        return Verifier(lambda: 
            pub_key.verify(sig_bytes, tbs_cert.dump())
        )

    def get_dsa_verifier(pub_key: ecc.EllipticCurvePublicKey, tbs_cert: x509.TbsCertificate, sig_bytes: bytes):
        sig_algo  = tbs_cert['signature']
        hash_algo = _STR_TO_HASH_ALGO[sig_algo.hash_algo]
        return Verifier(lambda: 
            pub_key.verify(sig_bytes, tbs_cert.dump(), hash_algo)
        )

    
    # Get signature verifier
    tbs_cert       = issued_cert['tbs_certificate']
    sig_bytes      = issued_cert.signature
    issuer_pub_key = load_der_public_key(issuing_cert.public_key.dump(), default_backend())

    if isinstance(issuer_pub_key, rsa.RSAPublicKey):
        verifier = get_rsa_verifier(issuer_pub_key, tbs_cert, sig_bytes)
    elif isinstance(issuer_pub_key, ecc.EllipticCurvePublicKey):
        verifier = get_ecdsa_verifier(issuer_pub_key, tbs_cert, sig_bytes)
    elif isinstance(issuer_pub_key, ed25519.Ed25519PublicKey):
        verifier = get_eddsa_verifier(issuer_pub_key, tbs_cert, sig_bytes)
    else:
        verifier = get_dsa_verifier(issuer_pub_key, tbs_cert, sig_bytes)
    
    # Verify cert sig
    try:
        verifier.verify()
    except cryptography_exceptions.InvalidSignature:
        return False
    return True