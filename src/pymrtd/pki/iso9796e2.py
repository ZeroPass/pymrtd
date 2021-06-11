from typing import Tuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from math import ceil

class Dss1VerifierError(Exception):
    pass

class Dss1Verifier:
    """ Implementation of ISO 9796-2 digital signature scheme 1. """

    # ISO/IEC 10118 UIDs
    TRAILER_IMPLICIT   = 0xBC
    TRAILER_SHA1       = 0x33CC
    TRAILER_SHA256     = 0x34CC
    TRAILER_SHA512     = 0x35CC
    TRAILER_SHA384     = 0x36CC
    TRAILER_SHA224     = 0x38CC
    TRAILER_SHA512_224 = 0x39CC
    TRAILER_SHA512_256 = 0x3ACC

    def __init__(self, publicKey: rsa.RSAPublicKey):
        if not isinstance(publicKey, rsa.RSAPublicKey):
            raise ValueError("publicKey must be instance of RSAPublicKey")
        self._pub_key = publicKey

    def verifySignature(self, message: bytes, signature: bytes) -> bool:
        """
        Verifies if signature is valid.
        :param message: Message to verify signature against
        :param signature:
        :return: True if signature is valid, otherwise False
        """
        try:
            self.recover_M1(message, signature)
            return True
        except:
            return False

    def recover_M1(self, message: bytes, signature: bytes) -> bytes:
        """
        Recovers message M1 from the signature.
        :param message: Message to verify signature against
        :param signature:
        :return: Recovered message M1
        :raises: Dss1VerifierError - if recovering message M1 fails
        """

        # Recover message representative F
        F = self._recover_F(signature)

        # Verify header
        if not Dss1Verifier._F_is_valid_header(F):
            raise Dss1VerifierError("Invalid header of recovered message representative")

        # Verify tail
        if not Dss1Verifier._F_is_valid_tail(F):
            raise Dss1VerifierError("Invalid trailer field of recovered message representative")

        # Get trailer size t and hash algorithm
        t = Dss1Verifier._F_get_t_size(F) # trailer field = hash identifier (last 1 - 2 bytes)
        hash_algo = Dss1Verifier._F_get_hash_algo(F, t)

        partial_recovery = Dss1Verifier._F_is_partial_recovery(F)
        pad_len = Dss1Verifier._F_padding_len(F) # pad len in bit count
        if partial_recovery and pad_len >= 9:
            raise Dss1VerifierError("Padding too long")

        # Extract M1 & H, construct message M and verify M
        (M1,H) = Dss1Verifier._F_get_M1_and_H(F, pad_len, t, hash_algo)
        M = Dss1Verifier._construct_M(M1, message, partial_recovery)
        if not Dss1Verifier._verify_M(M, H, hash_algo):
            raise Dss1VerifierError("Integrity check of recovered message failed")
        return M1

    def _recover_F(self, sig: bytes):
        """
        Decrypts RSA signature and returns representative message F.
        Note: Implementation uses direct openssl interface of lib cryptography
        TODO: Evaluate if signature opening function specified in ISO 9796-2 paragraph B.5 (A.5 in 2002 publ.) should be implemented.
              See ICAO 9303-11 p24.
        """
        backend = self._pub_key._backend
        key = self._pub_key

        init = backend._lib.EVP_PKEY_encrypt_init
        crypt = backend._lib.EVP_PKEY_encrypt

        pkey_ctx = backend._lib.EVP_PKEY_CTX_new(
            key._evp_pkey, backend._ffi.NULL
        )

        backend.openssl_assert(pkey_ctx != backend._ffi.NULL)
        pkey_ctx = backend._ffi.gc(pkey_ctx, backend._lib.EVP_PKEY_CTX_free)
        res = init(pkey_ctx)
        backend.openssl_assert(res == 1)
        res = backend._lib.EVP_PKEY_CTX_set_rsa_padding(
            pkey_ctx, backend._lib.RSA_NO_PADDING
        )

        backend.openssl_assert(res > 0)
        buf_size = backend._lib.EVP_PKEY_size(key._evp_pkey)
        backend.openssl_assert(buf_size > 0)

        outlen = backend._ffi.new("size_t *", buf_size)
        buf = backend._ffi.new("unsigned char[]", buf_size)
        res = crypt(pkey_ctx, buf, outlen, sig, len(sig))
        if res <= 0:
            backend._consume_errors()
            raise Dss1VerifierError("Decrypting signature failed")

        F = backend._ffi.buffer(buf)[:outlen[0]]

        # TODO: Verify OpenSSL performs following check specified in ISO 9796-2 paragraph B.7 (A.7 in 2002 publ.):
        #I = int.from_bytes(F, byteorder="big")
        #if I % 16 != 12:
        #    raise Dss1VerifierError("Decrypting signature failed")
        #if I > 2**(len(sig)*8 - 1) - 1:
        #    raise Dss1VerifierError("Decrypting signature failed")

        return F

    def _construct_M(M1: bytes, M2: bytes, partial_recovery: bool):
        ''' Constructs message M from M1 and M2 '''
        if partial_recovery:
            return M1 + M2
        else:
            M = M1
            if M != M2:
                raise Dss1VerifierError("Provided message and recovered message don't match")
            return M

    def _get_hash_algo(T: int) -> hashes.HashAlgorithm:
        hash_algo = None
        if T == Dss1Verifier.TRAILER_IMPLICIT or T == Dss1Verifier.TRAILER_SHA1:
            hash_algo = hashes.SHA1()
        elif T == Dss1Verifier.TRAILER_SHA224:
            hash_algo = hashes.SHA224()
        elif T == Dss1Verifier.TRAILER_SHA256:
            hash_algo = hashes.SHA256()
        elif T == Dss1Verifier.TRAILER_SHA384:
            hash_algo = hashes.SHA384()
        elif T == Dss1Verifier.TRAILER_SHA512:
            hash_algo = hashes.SHA512()
        elif T == Dss1Verifier.TRAILER_SHA512_224:
            hash_algo = hashes.SHA512_224()
        elif T == Dss1Verifier.TRAILER_SHA512_256:
            hash_algo = hashes.SHA512_256()

        if hash_algo is None:
            raise Dss1VerifierError("Unrecognized hash algorithm in signature")
        return hash_algo

    def _F_get_M1_and_H(F: bytes, pad_len: int, t: int, hash_algo: hashes.HashAlgorithm) -> Tuple[bytes, bytes]:
        ''' Returns tuple message M1 and hash H of message M '''
        # Remove padding bits
        F   = Dss1Verifier._F_remove_padding(F, pad_len)
        Lh  = hash_algo.digest_size
        Lm1 = len(F)  - (Lh + t)
        M1  = F[0 : Lm1]
        H   = F[Lm1 : Lm1 + Lh]
        return (M1, H)

    def _F_get_hash_algo(F: bytes, t: int):
        return Dss1Verifier._get_hash_algo(int.from_bytes(F[-t:], byteorder='big'))

    def _F_get_t_size(F: bytes):
        return 1 if F[-1] == 0xBC else 2 # trailer field = hash identifier (last 1 - 2 bytes)

    def _F_is_valid_header(F: bytes):
        ''' Check header, left most tw bits must be equal to '01 '''
        return ((F[0] & 0xC0) ^ 0x40) == 0

    def _F_is_valid_tail(F: bytes):
        ''' Check that nibble of the trailing byte ends with 0xC '''
        return ((F[-1] & 0xF) ^ 0xC) == 0

    def _F_is_partial_recovery(F: bytes):
        return (F[0] & 0x20) == 0x20  # bit 5 is set in case of partial recovery

    def _F_padding_len(F: bytes):
        """ Returns padding length in bit count. """
        c = 0

        # If padding is present the right most bit of the left most nibble is 0
        if (F[0] & 0x10) == 0:
            # Operate on nibbles
            for i in range(1, len(F) * 4):
                b = F[int((i * 4) / 8)]
                n = 0
                if i % 2 == 0:
                    n = (b >> 4) & 0x0F # left nibble
                else:
                    n = b & 0xF # right nibble
                c += 1
                if n != 0xB:
                    break
        return c * 4

    def _F_remove_padding(F: bytes, padBitCount: int):
        """:param padBitCount: Number of padding bits """
        if padBitCount < 1:
            return F
        nr = int(padBitCount / 4) + 1 # 1 nibble == header
        br = int(ceil(nr * 4 / 8))
        return F[br:]

    def _verify_M(M: bytes, H: bytes, hash_algo: hashes.HashAlgorithm) -> bool:
        h = hashes.Hash(hash_algo, backend=default_backend())
        h.update(M)
        return h.finalize() == H