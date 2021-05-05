from asn1crypto.algos import SignedDigestAlgorithm
from cryptography.hazmat.primitives import hashes

_STR_TO_HASH_ALGO = {
    'md5'        : hashes.MD5(),
    'sha1'       : hashes.SHA1(),
    'sha224'     : hashes.SHA224(),
    'sha256'     : hashes.SHA256(),
    'sha384'     : hashes.SHA384(),
    'sha512'     : hashes.SHA512(),
    'sha512_224' : hashes.SHA512_224(),
    'sha512_256' : hashes.SHA512_256(),
    'sha3_224'   : hashes.SHA3_224(),
    'sha3_256'   : hashes.SHA3_256(),
    'sha3_384'   : hashes.SHA3_384(),
    'sha3_512'   : hashes.SHA3_512(),
}

def get_hash_algo_by_name(hash_algo: str):
    hash_algo = hash_algo.lower()
    if hash_algo not in _STR_TO_HASH_ALGO:
        raise ValueError("Invalid hash algorithm '{}'".format(hash_algo))
    return _STR_TO_HASH_ALGO[hash_algo]

def update_sig_algo_if_no_hash_algo(sig_algo: SignedDigestAlgorithm, hash_algo: str):
    n_sig_algo = sig_algo['algorithm'].native 
    if n_sig_algo  == 'rsassa_pkcs1v15' or n_sig_algo == 'ecdsa' or n_sig_algo == 'dsa':
        if n_sig_algo == 'rsassa_pkcs1v15':
            n_sig_algo = 'rsa'

        if hash_algo == 'md5':
            sig_algo = SignedDigestAlgorithm({'algorithm': 'md5_' + n_sig_algo})
        elif hash_algo == 'sha1':
            sig_algo = SignedDigestAlgorithm({'algorithm': 'sha1_' + n_sig_algo})
        elif hash_algo == 'sha224':
            sig_algo = SignedDigestAlgorithm({'algorithm': 'sha224_' + n_sig_algo})
        elif hash_algo == 'sha256':
            sig_algo = SignedDigestAlgorithm({'algorithm': 'sha256_' + n_sig_algo})
        elif hash_algo == 'sha384':
            sig_algo = SignedDigestAlgorithm({'algorithm': 'sha384_' + n_sig_algo})
        elif hash_algo == 'sha512':
            sig_algo = SignedDigestAlgorithm({'algorithm': 'sha512_' + n_sig_algo})
        elif hash_algo == 'sha3_224':
            sig_algo = SignedDigestAlgorithm({'algorithm': 'sha3_224_' + n_sig_algo})
        elif hash_algo == 'sha3_256':
            sig_algo = SignedDigestAlgorithm({'algorithm': 'sha3_256_' + n_sig_algo})
        elif hash_algo == 'sha3_384':
            sig_algo = SignedDigestAlgorithm({'algorithm': 'sha3_384_' + n_sig_algo})
        elif hash_algo == 'sha3_512':
            sig_algo = SignedDigestAlgorithm({'algorithm': 'sha3_512_' + n_sig_algo})
    return sig_algo