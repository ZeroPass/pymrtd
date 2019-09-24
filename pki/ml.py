from asn1crypto import cms
from asn1crypto.algos import SignedDigestAlgorithm
import asn1crypto.core as asn1


from .x509 import CscaCertificate, MasterListSignerCertificate
from .cert_utils import verify_sig

class CertList(asn1.SetOf):
    _child_spec = CscaCertificate

class CscaList(asn1.Sequence):
    _fields = [
        ('version', asn1.Integer),
        ('certList', CertList)
    ]

    def version(self) -> int:
        return super().__getitem__('version').native

    def __len__(self):
        return len(self._get_list())

    def __getitem__(self, key):
        return self._get_list().__getitem__(key)

    def __iter__(self):
        return self._get_list().__iter__()

    def _get_list(self) -> CertList:
        return super().__getitem__('certList')


class CscaMasterListError(Exception):
    pass

class CscaMasterList():
    def __init__(self, cms_bytes):
        self._cms = cms.ContentInfo.load(cms_bytes)

        ctype = self._cms['content_type'].native
        if ctype != 'signed_data': # ICAO 9303-12-p25
            raise CscaMasterListError("Invalid master list content type: {}, should be 'signed_data'".format(ctype))

        cver = self._cms['content']['version'].native
        if cver != 'v3': # ICAO 9303-12-p25
            raise CscaMasterListError("Invalid SignedData version: {}, should be 'v3'".format(cver))

        econt_type = self._cms['content']['encap_content_info']['content_type'].native
        if econt_type != '2.23.136.1.1.2': # ICAO 9303-12-p26
            raise CscaMasterListError("Invalid encapContentInfo type: {}, should be '2.23.136.1.1.2'".format(econt_type))

        econt        = self._cms['content']['encap_content_info']['content'].native
        self._cscal  = CscaList.load(econt)
        if self._cscal.version() != 0: # ICAO 9303-12-p27
            raise CscaMasterListError("Unsupported encapContentInfo version: {}, should be 0".format(self._cscal.version()))
        
        self._mls_certs = []
        certs = self._cms['content']['certificates']
        if len(certs) < 1:
            raise CscaMasterListError("No master list signing certificate found") 

        for cc in certs:
            cc.chosen.__class__ = MasterListSignerCertificate
            self._mls_certs.append(cc.chosen)

    def getSigCertificates(self):
        return self._mls_certs

    def getCscaList(self):
        return self._cscal



