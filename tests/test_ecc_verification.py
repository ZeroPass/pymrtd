from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from pymrtd.pki import keys


def _generate_key_sign_and_serialize():
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    message = b"pymrtd test message for ECDSA verification"
    signature = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    pub = priv.public_key()
    pub_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return message, signature, pub_der


def test_ec_verify_x962_signature():
    message, signature, pub_der = _generate_key_sign_and_serialize()
    pub_key = keys.PublicKey.load(pub_der)
    sig_algo = keys.SignatureAlgorithm({"algorithm": "sha256_ecdsa"})
    assert pub_key.verifySignature(message, signature, sig_algo)


def test_ec_verify_plain_signature():
    message, signature, pub_der = _generate_key_sign_and_serialize()
    x962 = keys.ECDSA_X962_Signature.load(signature)
    plain_sig = x962.toPlain()
    pub_key = keys.PublicKey.load(pub_der)
    sig_algo_plain = keys.SignatureAlgorithm({"algorithm": "sha256_plain_ecdsa"})
    assert pub_key.verifySignature(message, plain_sig, sig_algo_plain)
