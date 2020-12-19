from asn1crypto import x509
from pymrtd.pki import keys

def verify_sig(signing_cert: x509.Certificate, msg_bytes: bytes, sig_bytes: bytes, sig_algo: keys.SignatureAlgorithm):
    """
    Verifies digital signature of message against public key of the signing certificate.
    It returns True if verification succeeds, otherwise False.
    """
    pub_key = keys.PublicKey.load(signing_cert.public_key.dump())
    if pub_key.isEcKey():
        sig_bytes = keys.ECDSA_X962_Signature.load(sig_bytes).toPlain()
        sig_algo = keys.SignatureAlgorithm({ 'algorithm' : sig_algo.hash_algo + "_plain_ecdsa"})
    return pub_key.verifySignature(msg_bytes, sig_bytes, sig_algo)


def verify_cert_sig(issued_cert: x509.Certificate, issuing_cert: x509.Certificate) -> bool:
    """
    Verifies digital signature of issued certificate against public key of the issuing certificate.
    It returns True if verification succeeds, otherwise False.
    """
    tbs_cert  = issued_cert['tbs_certificate']
    sig_algo  = tbs_cert['signature']
    sig_bytes = issued_cert.signature
    return verify_sig(issuing_cert, tbs_cert.dump(), sig_bytes, sig_algo)