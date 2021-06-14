import random
import pytest
from pymrtd import ef
from pymrtd.pki.iso9796e2 import *
from pymrtd.pki.keys import PublicKey
from random import randbytes, randint

def __test_dss1_sig_verification(pub_key, msg, sig, M1):
    dss1_verifier = Dss1Verifier(pub_key._pub_key)
    rec_M1 = dss1_verifier.recover_M1(msg, sig)
    assert rec_M1 == M1
    assert dss1_verifier.verifySignature(msg, sig) == True

    # Bad sig test
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 0x01
    with pytest.raises(Dss1VerifierError) as exc_info:
        dss1_verifier.recover_M1(msg, bytes(bad_sig))
    assert exc_info.type is Dss1VerifierError
    assert exc_info.value.args[0] == 'Invalid header of recovered message representative' or exc_info.value.args[0] == 'Invalid trailer field of recovered message representative'
    assert dss1_verifier.verifySignature(msg, bad_sig) == False

    bad_sig = bytearray(sig)
    bad_sig[-1] ^= 0x01
    with pytest.raises(Dss1VerifierError) as exc_info:
        dss1_verifier.recover_M1(msg, bytes(bad_sig))
    assert exc_info.type is Dss1VerifierError
    assert exc_info.value.args[0] == 'Invalid header of recovered message representative' or exc_info.value.args[0] == 'Invalid trailer field of recovered message representative'
    assert dss1_verifier.verifySignature(msg, bad_sig) == False

    bad_sig = bytearray(sig)
    bad_sig[int(len(sig)/2)] ^= 0x01
    with pytest.raises(Dss1VerifierError) as exc_info:
        dss1_verifier.recover_M1(msg, bytes(bad_sig))
    assert exc_info.type is Dss1VerifierError
    assert exc_info.value.args[0] == 'Invalid header of recovered message representative' \
        or exc_info.value.args[0] == 'Invalid trailer field of recovered message representative' \
        or exc_info.value.args[0] == 'Unrecognized hash algorithm in signature'
    assert dss1_verifier.verifySignature(msg, bad_sig) == False

    # Bad msg test
    bad_msg = bytearray(msg)
    bad_msg[0] ^= 0x01
    with pytest.raises(Dss1VerifierError, match='Integrity check of recovered message failed'):
        dss1_verifier.recover_M1(bad_msg, sig)
    assert dss1_verifier.verifySignature(bad_msg, sig) == False

    bad_msg = bytearray(msg)
    bad_msg[-1] ^= 0x01
    with pytest.raises(Dss1VerifierError, match='Integrity check of recovered message failed'):
        dss1_verifier.recover_M1(bad_msg, sig)
    assert dss1_verifier.verifySignature(bad_msg, sig) == False

    bad_msg = bytearray(msg)
    bad_msg[int(len(msg)/2)] ^= 0x01
    with pytest.raises(Dss1VerifierError, match='Integrity check of recovered message failed'):
        dss1_verifier.recover_M1(bad_msg, sig)
    assert dss1_verifier.verifySignature(bad_msg, sig) == False

    with pytest.raises(Dss1VerifierError) as exc_info:
        dss1_verifier.recover_M1(bad_msg, bytes(bad_sig))
    assert exc_info.type is Dss1VerifierError
    assert exc_info.value.args[0] == 'Invalid header of recovered message representative' \
        or exc_info.value.args[0] == 'Invalid trailer field of recovered message representative' \
        or exc_info.value.args[0] == 'Unrecognized hash algorithm in signature'
    assert dss1_verifier.verifySignature(bad_msg, bad_sig) == False

@pytest.mark.depends(on=[
    #'tests/ef/dg1_test.py::test_dg15'
])
def test_iso9796e2():
    ## Test Dss1Verifier._recover_F
    # Test vector rsa public key random generated
    tv_rsa_pub_key = PublicKey.load(bytes.fromhex('30819f300d06092a864886f70d010101050003818d0030818902818100d94d889e88853dd89769a18015a0a2e6bf82bf356fe14f251fb4f5e2df0d9f9a94a68a30c428b39e3362fb3779a497eceaea37100f264d7fb9fb1a97fbf621133de55fdcb9b1ad0d7a31b379216d79252f5c527b9bc63d83d4ecf4d1d45cbf843e8474babc655e9bb6799cba77a47eafa838296474afc24beb9c825b73ebf5490203010001'))
    dss1_verifier = Dss1Verifier(tv_rsa_pub_key._pub_key)

    tv_f   = bytes.fromhex('2374657374205253412064656372797074696F6E20666F722070796D72746420756E69747465737400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    tv_rsa_enc = bytes.fromhex('31632744d140a834c6789b533b46919ce45fdd8d876b10f9d5ab9eb6fe4dbcc9438fe476778a2dcb500ac4b6e7ef9c38bddece5a57d13987f986e012c88f7c9dde5f3cfc5fc99c4d4c6164a17445764a475f1421a6e60f093fbabc3a37561adcefd78b4dd8b48feab8a2481547351b8192b2d7b5910749f400632dfd5bb3a11b')
    f = dss1_verifier._recover_F(tv_rsa_enc)
    assert f == tv_f

    tv_rsa_enc = bytes.fromhex('cbdd4bedcce00f58a52b4f584bdd710a478a55847087d3fadbdfbedd6056d9edafa09c86ea3ca0f65070dea3b1f39022482805a0646619b5f7fdf197f0475ee8ccda0000adb400209e2f464517c1bf0c42790e59c5d622ac7080463f7d082d9ba0dae9ebfeac4f82878bcb4b0940a4859960fb6777246173db038ebed0ef1f87')
    tv_f   = bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000002374657374205253412064656372797074696F6E20666F722070796D72746420756E6974746573740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    f = dss1_verifier._recover_F(tv_rsa_enc)
    assert f == tv_f

    tv_rsa_enc = bytes.fromhex('464c08e971f57b01561061326d3c0bd1c97105bd9cd7a8e2e9cc3e322ef83ff775c6393faba3874b4fe985a96155d398b49c3e5ae23de02117e6b62beec921bac0270dcc8524a5d33083093af12cd2a2f0647710e7a6dc79c1e70eda10719cad3b0d318500fcf1a365c77f16fd93714d561e684573192062f892eff2a5b80f03')
    tv_f   = bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002374657374205253412064656372797074696F6E20666F722070796D72746420756E697474657374')
    f = dss1_verifier._recover_F(tv_rsa_enc)
    assert f == tv_f

    # fuzz test
    with pytest.raises(Dss1VerifierError, match="Decrypting signature failed"):
        broken_sig = bytes()
        dss1_verifier._recover_F(broken_sig)

    with pytest.raises(Dss1VerifierError, match="Decrypting signature failed"):
        broken_sig = randbytes(64)
        dss1_verifier._recover_F(broken_sig)

    with pytest.raises(Dss1VerifierError, match="Decrypting signature failed"):
        broken_sig = randbytes(len(tv_rsa_enc) - 1)
        dss1_verifier._recover_F(broken_sig)

    with pytest.raises(Dss1VerifierError, match="Decrypting signature failed"):
        broken_sig = randbytes(len(tv_rsa_enc) + 1)
        dss1_verifier._recover_F(broken_sig)

    ## Test Dss1Verifier._get_hash_algo
    t = bytes.fromhex('BC')
    h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))
    assert isinstance(h, hashes.SHA1)

    t = bytes.fromhex('33CC')
    h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))
    assert isinstance(h, hashes.SHA1)

    t = bytes.fromhex('34CC')
    h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))
    assert isinstance(h, hashes.SHA256)

    t = bytes.fromhex('35CC')
    h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))
    assert isinstance(h, hashes.SHA512)

    t = bytes.fromhex('36CC')
    h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))
    assert isinstance(h, hashes.SHA384)

    t = bytes.fromhex('38CC')
    h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))
    assert isinstance(h, hashes.SHA224)

    t = bytes.fromhex('39CC')
    h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))
    assert isinstance(h, hashes.SHA512_224)

    t = bytes.fromhex('3ACC')
    h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))
    assert isinstance(h, hashes.SHA512_256)

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        t = bytes.fromhex('')
        h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        t = bytes.fromhex('CC')
        h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        t = bytes.fromhex('CCCC')
        h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        t = bytes.fromhex('30CC')
        h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        t = bytes.fromhex('31CC')
        h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        t = bytes.fromhex('32CC')
        h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        t = bytes.fromhex('37CC')
        h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        t = bytes.fromhex('3BCC')
        h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        t = bytes.fromhex('3CCC')
        h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        t = bytes.fromhex('3DCC')
        h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        t = bytes.fromhex('3ECC')
        h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        t = bytes.fromhex('3FCC')
        h = Dss1Verifier._get_hash_algo(int.from_bytes(t, byteorder='big'))

    # Test vector F taken from ICAO 9303 p11 appendix F to Part 11
    F = bytes.fromhex('6A9D2784A67F8E7C659973EA1AEA25D95B6C8F91E5002F369F0FBDCE8A3CEC1991B543F1696546C5524CF23A5303CD6C98599F40B79F377B5F3A1406B3B4D8F96784D23AA88DB7E1032A405E69325FA91A6E86F5C71AEA978264C4A207446DAD4E7292E2DCDA3024B47DA8C063AA1E6D22FBD976AB0FE73D94D2D9C6D88127BC')

    ## Test Dss1Verifier._F_is_valid_header
    assert Dss1Verifier._F_is_valid_header(F)                   == True
    assert Dss1Verifier._F_is_valid_header(bytes.fromhex('40')) == True
    assert Dss1Verifier._F_is_valid_header(bytes.fromhex('00')) == False
    assert Dss1Verifier._F_is_valid_header(bytes.fromhex('BF')) == False
    with pytest.raises(IndexError, match="index out of range"):
        Dss1Verifier._F_is_valid_header(bytes.fromhex(''))

    ## Test Dss1Verifier._F_is_valid_tail
    assert Dss1Verifier._F_is_valid_tail(F)                   == True
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('0C')) == True
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('1C')) == True
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('AC')) == True
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('BC')) == True
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('CC')) == True
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('FC')) == True
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('FC')) == True
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('00')) == False
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('10')) == False
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('B0')) == False
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('C0')) == False
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('A0')) == False
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('F0')) == False
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('01')) == False
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('0A')) == False
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('0B')) == False
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('0D')) == False
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('0E')) == False
    assert Dss1Verifier._F_is_valid_tail(bytes.fromhex('0F')) == False
    with pytest.raises(IndexError, match="index out of range"):
        Dss1Verifier._F_is_valid_tail(bytes.fromhex(''))

    ## Test Dss1Verifier._F_padding_len
    assert Dss1Verifier._F_padding_len(F) == 4
    assert Dss1Verifier._F_padding_len(bytes.fromhex('00')) == 4
    assert Dss1Verifier._F_padding_len(bytes.fromhex('10')) == 0
    assert Dss1Verifier._F_padding_len(bytes.fromhex('EF')) == 4
    assert Dss1Verifier._F_padding_len(bytes.fromhex('0BA0')) == 8
    assert Dss1Verifier._F_padding_len(bytes.fromhex('0BBBBBBA')) == 28
    assert Dss1Verifier._F_padding_len(bytes.fromhex('0BBBBBBBA0')) == 32
    with pytest.raises(IndexError, match="index out of range"):
        Dss1Verifier._F_padding_len(bytes.fromhex('0B'))

    ## Test Dss1Verifier._F_remove_padding
    assert Dss1Verifier._F_remove_padding(bytes.fromhex('00'), 4) == b''
    assert Dss1Verifier._F_remove_padding(bytes.fromhex('10'), 4) == b''
    assert Dss1Verifier._F_remove_padding(bytes.fromhex('6A'), 4) == b''
    assert Dss1Verifier._F_remove_padding(bytes.fromhex('EF'), 4) == b''
    assert Dss1Verifier._F_remove_padding(bytes.fromhex('0BA0'), 8) == b''
    assert Dss1Verifier._F_remove_padding(bytes.fromhex('0BBBBBBA'), 28) == b''
    assert Dss1Verifier._F_remove_padding(bytes.fromhex('0BBBBBBA00'), 28) == bytes.fromhex('00')
    assert Dss1Verifier._F_remove_padding(bytes.fromhex('0BBBBBBBA0'), 32) == b''
    assert Dss1Verifier._F_remove_padding(bytes.fromhex('0BBBBBBBA000'), 32) == bytes.fromhex('00')
    assert Dss1Verifier._F_remove_padding(bytes.fromhex('0BBBBBBBA001FF'), 32) == bytes.fromhex('01FF')
    assert Dss1Verifier._F_remove_padding(F, 4)          == bytes.fromhex('9D2784A67F8E7C659973EA1AEA25D95B6C8F91E5002F369F0FBDCE8A3CEC1991B543F1696546C5524CF23A5303CD6C98599F40B79F377B5F3A1406B3B4D8F96784D23AA88DB7E1032A405E69325FA91A6E86F5C71AEA978264C4A207446DAD4E7292E2DCDA3024B47DA8C063AA1E6D22FBD976AB0FE73D94D2D9C6D88127BC')
    Dss1Verifier._F_remove_padding(bytes.fromhex(''), 4) == b'' # should not throw

    ## Test Dss1Verifier._F_is_partial_recovery, requires the bit 5 being set in the first byte
    assert Dss1Verifier._F_is_partial_recovery(F)                   == True
    assert Dss1Verifier._F_is_partial_recovery(bytes.fromhex('20')) == True
    assert Dss1Verifier._F_is_partial_recovery(bytes.fromhex('00')) == False
    assert Dss1Verifier._F_is_partial_recovery(bytes.fromhex('DF')) == False
    assert Dss1Verifier._F_is_partial_recovery(bytes.fromhex('FF')) == True
    with pytest.raises(IndexError, match="index out of range"):
        Dss1Verifier._F_is_partial_recovery(bytes.fromhex(''))

    ## Test Dss1Verifier._F_padding_len
    assert Dss1Verifier._F_get_t_size(F)                       == 1
    assert Dss1Verifier._F_get_t_size(bytes.fromhex('BC'))     == 1
    assert Dss1Verifier._F_get_t_size(bytes.fromhex('BCBC'))   == 1
    assert Dss1Verifier._F_get_t_size(bytes.fromhex('CCBC'))   == 1
    assert Dss1Verifier._F_get_t_size(bytes.fromhex('00BC'))   == 1
    assert Dss1Verifier._F_get_t_size(bytes.fromhex('00BCBC')) == 1
    assert Dss1Verifier._F_get_t_size(bytes.fromhex('FFBCBC')) == 1
    assert Dss1Verifier._F_get_t_size(bytes.fromhex('00CCBC')) == 1
    assert Dss1Verifier._F_get_t_size(bytes.fromhex('AABCCC')) == 2
    assert Dss1Verifier._F_get_t_size(bytes.fromhex('BCCC'))   == 2
    assert Dss1Verifier._F_get_t_size(bytes.fromhex('00BCCC')) == 2
    assert Dss1Verifier._F_get_t_size(bytes.fromhex('AABCCC')) == 2
    assert Dss1Verifier._F_get_t_size(randbytes(randint(8, 256)) + bytes.fromhex('BC')) == 1
    assert Dss1Verifier._F_get_t_size(randbytes(randint(8, 256)) + bytes.fromhex('CC')) == 2

    with pytest.raises(IndexError, match="index out of range"):
        Dss1Verifier._F_get_t_size(bytes.fromhex(''))

    ## Test Dss1Verifier._F_get_hash_algo
    FF = bytes.fromhex('BC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA1)

    FF = bytes.fromhex('AA00BBBC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA1)

    FF = randbytes(randint(8, 256)) + bytes.fromhex('BC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA1)

    FF = F
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA1)

    FF = bytes.fromhex('33CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA1)

    FF = bytes.fromhex('AABB3333CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA1)

    FF = randbytes(randint(8, 256)) + bytes.fromhex('33CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA1)

    FF = bytes.fromhex('34CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA256)

    FF = bytes.fromhex('AABB3434CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA256)

    FF = randbytes(randint(8, 256)) + bytes.fromhex('34CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA256)

    FF = bytes.fromhex('35CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA512)

    FF = bytes.fromhex('AABB3535CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA512)

    FF = randbytes(randint(8, 256)) + bytes.fromhex('35CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA512)

    FF = bytes.fromhex('36CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA384)

    FF = bytes.fromhex('AABB3636CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA384)

    FF = randbytes(randint(8, 256)) + bytes.fromhex('36CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA384)

    FF = bytes.fromhex('38CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA224)

    FF = bytes.fromhex('AABB3838CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA224)

    FF = randbytes(randint(8, 256)) + bytes.fromhex('38CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA224)

    FF = bytes.fromhex('39CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA512_224)

    FF = bytes.fromhex('AABB3939CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA512_224)

    FF = randbytes(randint(8, 256)) + bytes.fromhex('39CC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA512_224)

    FF = bytes.fromhex('3ACC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA512_256)

    FF = bytes.fromhex('AABB3A3ACC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA512_256)

    FF = randbytes(randint(8, 256)) + bytes.fromhex('3ACC')
    h = Dss1Verifier._F_get_hash_algo(FF, Dss1Verifier._F_get_t_size(FF))
    assert isinstance(h, hashes.SHA512_256)

    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        Dss1Verifier._F_get_hash_algo(bytes.fromhex(''), 1)
    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        Dss1Verifier._F_get_hash_algo(bytes.fromhex('CC'), 1)
    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        Dss1Verifier._F_get_hash_algo(bytes.fromhex('CCCC'), 2)
    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        Dss1Verifier._F_get_hash_algo(bytes.fromhex('30CC'), 2)
    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        Dss1Verifier._F_get_hash_algo(bytes.fromhex('31CC'), 2)
    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        Dss1Verifier._F_get_hash_algo(bytes.fromhex('32CC'), 2)
    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        Dss1Verifier._F_get_hash_algo(bytes.fromhex('37CC'), 2)
    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        Dss1Verifier._F_get_hash_algo(bytes.fromhex('3BCC'), 2)
    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        Dss1Verifier._F_get_hash_algo(bytes.fromhex('3CCC'), 2)
    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        Dss1Verifier._F_get_hash_algo(bytes.fromhex('3DCC'), 2)
    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        Dss1Verifier._F_get_hash_algo(bytes.fromhex('3ECC'), 2)
    with pytest.raises(Dss1VerifierError, match="Unrecognized hash algorithm in signature"):
        Dss1Verifier._F_get_hash_algo(bytes.fromhex('3FCC'), 2)

    ## Test Dss1Verifier._F_get_M1_and_H
    pad_len = Dss1Verifier._F_padding_len(F)
    t = Dss1Verifier._F_get_t_size(F)
    hash_algo = Dss1Verifier._F_get_hash_algo(F, t)
    (M1,H) = Dss1Verifier._F_get_M1_and_H(F, pad_len, t, hash_algo)
    assert M1 == bytes.fromhex('9D2784A67F8E7C659973EA1AEA25D95B6C8F91E5002F369F0FBDCE8A3CEC1991B543F1696546C5524CF23A5303CD6C98599F40B79F377B5F3A1406B3B4D8F96784D23AA88DB7E1032A405E69325FA91A6E86F5C71AEA978264C4A207446DAD4E7292E2DCDA3024B47DA8')
    assert H  == bytes.fromhex('C063AA1E6D22FBD976AB0FE73D94D2D9C6D88127')

    ## Test Dss1Verifier._construct_M
    M = Dss1Verifier._construct_M(M1, M1, partial_recovery=False)
    assert M == M1

    with pytest.raises(Dss1VerifierError, match="Provided message and recovered message don't match"):
        Dss1Verifier._construct_M(M1, b'', False)

    M = Dss1Verifier._construct_M(M1, bytes.fromhex('F173589974BF40C6'), partial_recovery=True)
    assert M == bytes.fromhex('9D2784A67F8E7C659973EA1AEA25D95B6C8F91E5002F369F0FBDCE8A3CEC1991B543F1696546C5524CF23A5303CD6C98599F40B79F377B5F3A1406B3B4D8F96784D23AA88DB7E1032A405E69325FA91A6E86F5C71AEA978264C4A207446DAD4E7292E2DCDA3024B47DA8F173589974BF40C6')

    M = Dss1Verifier._construct_M(M1, bytes.fromhex('F173589974BF40C6'), partial_recovery=Dss1Verifier._F_is_partial_recovery(F))
    assert M == bytes.fromhex('9D2784A67F8E7C659973EA1AEA25D95B6C8F91E5002F369F0FBDCE8A3CEC1991B543F1696546C5524CF23A5303CD6C98599F40B79F377B5F3A1406B3B4D8F96784D23AA88DB7E1032A405E69325FA91A6E86F5C71AEA978264C4A207446DAD4E7292E2DCDA3024B47DA8F173589974BF40C6')



    ## Test Dss1Verifier._verify_M
    assert Dss1Verifier._verify_M(M, H, hash_algo) == True

    BM = bytearray(M)
    BM[0] ^= 0x01
    assert Dss1Verifier._verify_M(BM, H, hash_algo) == False

    BM = bytearray(M)
    BM[-1] ^= 0x01
    assert Dss1Verifier._verify_M(BM, H, hash_algo) == False

    BM = bytearray(M)
    BM[int(len(BM)/2)] ^= 0x01
    assert Dss1Verifier._verify_M(BM, H, hash_algo) == False

    BH = bytearray(H)
    BH[0] ^= 0x01
    assert Dss1Verifier._verify_M(M, BH, hash_algo) == False

    BH = bytearray(H)
    BH[-1] ^= 0x01
    assert Dss1Verifier._verify_M(M, BH, hash_algo) == False

    BH = bytearray(H)
    BH[int(len(BH)/2)] ^= 0x01
    assert Dss1Verifier._verify_M(M, BH, hash_algo) == False

    ## Test Dss1Verifier.recover_M1 & Dss1Verifier.verifySignature
    # Test vectors taken from real biometric passport
    rawDg15 = bytes.fromhex("6F81A230819F300D06092A864886F70D010101050003818D0030818902818100BD8620D45693E1CD8678639F22E9553F09E3AFD87BD26000113CE2798B7A02A2E0AB6B7525D09072109D938D6708167E8FAFAF83F17BFBA36CECCE26058C7ED9AE29516755B19F78CE0E73DA02340B117B8AB2ECA007F1390E93E896016335EB5C1E330B961C03E253D17874F7ABEE8D4962C49FFE578D46954FF23B26F5E5550203010001")
    pub_key = ef.DG15.load(rawDg15).aaPublicKey
    assert pub_key.isRsaKey() == True

    dss1_verifier = Dss1Verifier(pub_key._pub_key)
    msg = bytes.fromhex('47E4EE7F211F7326')
    sig = bytes.fromhex('8AECE4E0AB1A6B9E06B31ACBA51AE316D0B7B48E2F5FE13E575060F6B9DC27A2F9D03DCF67A141F466EEC753879106BE0992F46F5EAAD075EB1886D2ACE90D60C2EDA69880780CE4FA36EF27AB01C47527BD23B178EC8F213307281572C219487FC11B2C3D9C144DC98D96D1A79A7478449D692D3D14E8C044F81B3ADF0047E0')
    M1  = bytes.fromhex('60735d54c4fc7759a2093c4b6f6f09dac2ddb103bd14b512e5683aed8ed7eb8fd3dd6bf122dadf8c2c43d359f8f6e6537dadec03d21b385a9b3bf6111751558f860ce3701574d742962110ad81d08f13e5e9439d912ac2b3f61d60cc48700f5260a82ca06362dd077e75')
    __test_dss1_sig_verification(pub_key, msg, sig, M1)

    msg = bytes.fromhex('5DD17658F6E21C13')
    sig = bytes.fromhex('97251259E9EB453A8DC2D9CD85D5A49D2E83F31D6465CB1FBD09C5E7800D4F0FB9FF7312343CD3955CA3BE6768AD7938F3D36B0C9E2205923786949B5F48FBF1C94D01B5BC9DA88C8293E118F87E14E4CC409D52AA7ED266E20248AB3C04949838540DEB24588436607EA620B4825D002C5FAB4F07B618D72C0A9EC247653FE7')
    M1 = bytes.fromhex('51d3acac47e1f3b2f438218d4deb5386f6a53d74271c4c2498c86c721f485f0332ff4d1ab94b559fbf4c6c73917647eaa09ff5d179fb7a5e84327b6ded162a967ef0fd78d8f3f05cb360a4aa78651f4464c830a62575d4fbea6fe56f6021e50970925c7447b7d0274f68')
    __test_dss1_sig_verification(pub_key, msg, sig, M1)

    msg = bytes.fromhex('18BD6C81F37598E2')
    sig = bytes.fromhex('12C0972DFE9E1DDB42B46130D64339E0845578D85E5F0ED7C9E12036AE0C3D417BBAAA6CA5579E782DDEADA825E432C2AE9593B8DB5806327E22B18CD0AB86353C314925A01390806A1D6E8DDE2CD0D82D9671457139241E93BC308E5573C335D14EF6182A5171A443A82A2568D6B1373A1F227377C584ABA7B1E8B1F47E393F')
    M1  = bytes.fromhex('097d0235b982189b854a80e67ad9087b22590b49279727d471c12fa40412c499aefc6a38faacb1e5042b9fb06826c678dca36e61e16ea3a7c17ead774a28f66a6a21d2277355ce134b59d8953dda7ce37ea836210aa3a2abed9159e91ea047223dcb16578537864642b2')
    __test_dss1_sig_verification(pub_key, msg, sig, M1)

    msg = bytes.fromhex('0A2756299542EFCF')
    sig = bytes.fromhex('0854CF7B69FB54286F97FC8B396722E21156DFEEC38CF5C63035B09A59C4EA7FCA79865D5EE166548AAE5AE1F629A57459B46F5D1D1E4EFE9369C0075903D3CA282D6B2CF5843E62CE53BEA33E3D6AA7A48147CC38C9B534437FD0DCD0F0C787BE74061DFA844435253D651E7986BA47F49FA49D7041BD1FE72B5E5D09221FD1')
    M1  = bytes.fromhex('6ed132d3836b72e561edfb1948b8cfc6049de6d00a724a9747f13fb2ad26676455bf1bf2a7b29a5b27b34c893bdabee203e1c8a20ffb277971363fc74543ac6419916ae2179360252519e25e4f2e5534810071072a34c25b92773e61f6ab75c35da4238bd78eb6cbbdde')
    __test_dss1_sig_verification(pub_key, msg, sig, M1)

    # Test vectors taken from Bouncy Castle Crypto Package For Java
    # https://github.com/bcgit/bc-java/blob/6357e5c9eb70aa6904711972dfd50523e62a6a6b/core/src/test/java/org/bouncycastle/crypto/test/ISO9796Test.java#L789-L824
    pub_key = PublicKey.load(bytes.fromhex('30819f300d06092a864886f70d010101050003818d0030818902818100CDCBDABBF93BE8E8294E32B055256BBD0397735189BF75816341BB0D488D05D627991221DF7D59835C76A4BB4808ADEEB779E7794504E956ADC2A661B46904CDC71337DD29DDDD454124EF79CFDD7BC2C21952573CEFBA485CC38C6BD2428809B5A31A898A6B5648CAA4ED678D9743B589134B7187478996300EDBA16271A8610203010001'))
    msg = bytes.fromhex('0000000000000000')
    sig = bytes.fromhex('482E20D1EDDED34359C38F5E7C01203F9D6B2641CDCA5C404D49ADAEDE034C7481D781D043722587761C90468DE69C6585A1E8B9C322F90E1B580EEDAB3F6007D0C366CF92B4DB8B41C8314929DCE2BE889C0129123484D2FD3D12763D2EBFD12AC8E51D7061AFCA1A53DEDEC7B9A617472A78C952CCC72467AE008E5F132994')
    M1  = bytes.fromhex('539bb29260e7bc226c8798b01af2caaadc3675e26065e1e3856615894d5baef7d97634278d6dd609cf9091b68b248cc2f817ccc2e98ad7efa3b730ee97afc20ad5c00e24f8a49b89cdb05613b5ce2094cc21c9afb84a23c771be5ca500e8fb5d75f40d93cab6ee019569')
    __test_dss1_sig_verification(pub_key, msg, sig, M1)