import asn1crypto.core as asn1
from asn1crypto.util import int_from_bytes
from asn1crypto.keys import PublicKeyInfo

from .base import ElementaryFile
from pymrtd.pki import sig_utils, keys


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