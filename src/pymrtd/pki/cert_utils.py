from asn1crypto import x509
from pymrtd.pki import keys

def verify_sig(signing_cert: x509.Certificate, msg_bytes: bytes, sig_bytes: bytes, sig_algo: keys.SignatureAlgorithm) -> bool:
    """
    Verifies digital signature of message against public key of the signing certificate.
    :return: True if verification succeeds, otherwise False.
    :raises *Exception: If there was a problem in the process before signature is fully verified.
    """
    pub_key = keys.PublicKey.load(signing_cert.public_key.dump())
    if pub_key.isEcKey():
        sig_bytes = keys.ECDSA_X962_Signature.load(sig_bytes).toPlain()
        sig_algo = keys.SignatureAlgorithm({ 'algorithm' : sig_algo.hash_algo + "_plain_ecdsa"})
    return pub_key.verifySignature(msg_bytes, sig_bytes, sig_algo)


def verify_cert_sig(cert: x509.Certificate, issuerCert: x509.Certificate) -> bool:
    """
    Verifies digital signature of issued certificate against public key of the issuing certificate.
    :param cert: The certificate for which to verify the signature was generated by `issuing_cert`.
    :param issuing_cert: The certificate which issued `cert`.
    :return: True if verification succeeds, otherwise False.
    :raises *Exception: If there was a problem in the process before signature is fully verified.
    """
    tbs_cert  = cert['tbs_certificate']
    sig_algo  = tbs_cert['signature'] # Must use signed sig algorithm
    sig_bytes = cert.signature
    return verify_sig(issuerCert, tbs_cert.dump(), sig_bytes, sig_algo)
