from asn1crypto.keys import PublicKeyInfo

from pymrtd.pki import keys

from .dg import DataGroup


class DG15(DataGroup):
    tag = 15
    _content_spec = PublicKeyInfo
    _aakey: keys.AAPublicKey

    @property
    def aaPublicKeyInfo(self) -> PublicKeyInfo:
        """Returns active authentication public key info"""
        return self.content

    @property
    def aaPublicKey(self) -> keys.AAPublicKey:
        """Returns active authentication public key"""
        if not hasattr(self, "_aakey"):
            self._aakey = keys.AAPublicKey.load(self.aaPublicKeyInfo.dump())
        return self._aakey
