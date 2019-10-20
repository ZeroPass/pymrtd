import asn1crypto.core as asn1
from asn1crypto.util import int_from_bytes
from asn1crypto.keys import PublicKeyInfo

from .base import ElementaryFile
from pymrtd.pki import keys, oids, sig_utils

from typing import Union


class ActiveAuthenticationInfoId(asn1.ObjectIdentifier):
    _map = {
        oids.id_icao_mrtd_security_aaProtocolObject: 'aa_info',
    }


class ActiveAuthenticationInfo(asn1.Sequence):
    _fields = [
        ('protocol', ActiveAuthenticationInfoId),
        ('version', asn1.Integer),
        ('signature_algorithm', keys.SignatureAlgorithmId)
    ]


class ChipAuthenticationInfoId(asn1.ObjectIdentifier):
    _map = {
        oids.id_CA_DH_3DES_CBC_CBC       : 'ca_dh_3des_cbc_cbc',
        oids.id_CA_DH_AES_CBC_CMAC_128   : 'ca_dh_aes_cbc_cmac_128',
        oids.id_CA_DH_AES_CBC_CMAC_192   : 'ca_dh_aes_cbc_cmac_192',
        oids.id_CA_DH_AES_CBC_CMAC_256   : 'ca_dh_aes_cbc_cmac_256',
        oids.id_CA_ECDH_3DES_CBC_CBC     : 'ca_ecdh_3des_cbc_cbc',
        oids.id_CA_ECDH_AES_CBC_CMAC_128 : 'ca_ecdh_aes_cbc_cmac_128',
        oids.id_CA_ECDH_AES_CBC_CMAC_192 : 'ca_ecdh_aes_cbc_cmac_192',
        oids.id_CA_ECDH_AES_CBC_CMAC_256 : 'ca_ecdh_aes_cbc_cmac_256'
    }


class ChipAuthenticationInfo(asn1.Sequence):
    _fields = [
        ('protocol', ChipAuthenticationInfoId),
        ('version', asn1.Integer),
        ('key_id', asn1.Integer, {'optional': True})
    ]


class ChipAuthenticationPublicKeyInfoId(asn1.ObjectIdentifier):
    _map = {
        oids.id_PK_DH   : 'pk_dh',
        oids.id_PK_ECDH : 'pk_ecdh'
    }


class ChipAuthenticationPublicKeyInfo(asn1.Sequence):
    _fields = [
        ('protocol', ChipAuthenticationPublicKeyInfoId),
        ('chip_auth_public_key', PublicKeyInfo),
        ('key_id', asn1.Integer, {'optional': True})
    ]


class DefaultSecurityInfo(asn1.Sequence):
    _fields = [
        ('protocol', asn1.ObjectIdentifier),
        ('required_data', asn1.Any),
        ('optional', asn1.Any, {'optional': True})
    ]


class SecurityInfo(asn1.Choice):
    _alternatives = [
        ('security_info', DefaultSecurityInfo),
        ('aa_info', ActiveAuthenticationInfo),
        ('chip_auth_info', ChipAuthenticationInfo),
        ('chip_auth_pub_key_info', ChipAuthenticationPublicKeyInfo)
        #Note: Missing PACEDomainParameterInfo and PACEInfo 
    ]

    def validate(self, class_, tag, contents):
        oid = asn1.ObjectIdentifier.load(contents).dotted

        self._choice = 0
        for index, info in enumerate(self._alternatives):
            toidm = info[1]._fields[0][1]._map
            if toidm is not None and oid in toidm:
                self._choice = index
                return

    def parse(self):
        if self._parsed is None:
            super().parse()
            if self.name == 'aa_info' or self.name == 'chip_auth_info':
                if self._parsed['version'].native != 1:
                    from asn1crypto._types import type_name
                    raise ValueError("{} version != 1".format(type_name(self._parsed)))
        return self._parsed


class SecurityInfos(asn1.SetOf):
    _child_spec = SecurityInfo


class DataGroupNumber(asn1.Integer):
    _map = {
        1: 'dataGroup1',
        2: 'dataGroup2',
        3: 'dataGroup3',
        4: 'dataGroup4',
        5: 'dataGroup5',
        6: 'dataGroup6',
        7: 'dataGroup7',
        8: 'dataGroup8',
        9: 'dataGroup9',
        10: 'dataGroup10',
        11: 'dataGroup11',
        12: 'dataGroup12',
        13: 'dataGroup13',
        14: 'dataGroup14',
        15: 'dataGroup15',
        16: 'dataGroup16'
    }

    @property
    def value(self) -> int:
        return int_from_bytes(self.contents, signed=True)

    def __eq__(self, other) -> bool:
        if isinstance(other, int):
            return self.value == other
        elif isinstance(other, DataGroupNumber):
            return self.value == other.value
        return False

    def __ne__(self, other) -> bool:
        return not self.__eq__(other)


class DataGroup(ElementaryFile):
    class_ = 1
    method = 1

    @property
    def number(self) -> DataGroupNumber:
        return DataGroupNumber(self.tag)


class DG14(DataGroup):
    tag = 14
    content_spec = SecurityInfos

    @property
    def aaInfo(self) -> Union[ActiveAuthenticationInfo, None]:
        ''' Returns ActiveAuthenticationInfo if in list otherwise None. '''

        # Loop over list of SecurityInfo objects and try to find ActiveAuthentication object
        # Should contain only one ActiveAuthenticationInfo
        for si in self.content:
            if isinstance(si.chosen, ActiveAuthenticationInfo):
                return si
        return None

    @property
    def aaSignatureAlgo(self) -> keys.SignatureAlgorithm:
        ''' Returns SignatureAlgorithm object or None if DG doesn't contain one. '''

        aai = self.aaInfo
        if aai is None:
            return None

        # Get signature algorithm
        return keys.SignatureAlgorithm({ 'algorithm' : aai['signature_algorithm'] })



class DG15(DataGroup):
    tag = 15
    content_spec = PublicKeyInfo

    @property
    def aaPublicKeyInfo(self) -> PublicKeyInfo:
        ''' Returns active authentication public key info '''
        return self.content

    @property
    def aaPublicKey(self) -> keys.AAPublicKey:
        ''' Returns active authentication public key '''
        if not hasattr(self, '_aakey'):
            self._aakey = keys.AAPublicKey.load(self.aaPublicKeyInfo.dump())
        return self._aakey