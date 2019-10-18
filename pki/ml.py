from asn1crypto import cms
import asn1crypto.core as asn1

from .x509 import CscaCertificate, MasterListSignerCertificate
from .cms import SignedData, SignedDataError
from .oids import id_icao_cscaMasterList

from typing import NoReturn


class CertList(asn1.SetOf):
    _child_spec = CscaCertificate

class CscaList(asn1.Sequence):
    _fields = [
        ('version', asn1.Integer),
        ('certList', CertList)
    ]

    @property
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
    cms.ContentType._map[id_icao_cscaMasterList] = 'icaoCscaMasterList'
    cms.EncapsulatedContentInfo._oid_specs['icaoCscaMasterList'] = CscaList

    def __init__(self, cms_bytes):
        SignedData._certificate_type = MasterListSignerCertificate
        ci = cms.ContentInfo.load(cms_bytes)

        ctype = ci['content_type'].native
        if ctype != 'signed_data': # ICAO 9303-12-p25
            raise CscaMasterListError("Invalid master list content type: {}, should be 'signed_data'".format(ctype))

        self._sd = ci['content']
        cver = self._sd.version.native
        if cver != 'v3': # ICAO 9303-12-p25
            raise CscaMasterListError("Invalid SignedData version: {}, should be 'v3'".format(cver))

        if self._sd.contentType.dotted != id_icao_cscaMasterList:
            raise CscaMasterListError("Invalid encapContentInfo type: {}, should be '{}'".format(self._sd.contentType.dotted, id_icao_cscaMasterList))

        if self._sd.content.version != 0: # ICAO 9303-12-p27
            raise CscaMasterListError("Unsupported encapContentInfo version: {}, should be 0".format(self._sd.version))
        
        if len(self._sd.certificates) < 1:
            raise CscaMasterListError("No master list signer certificate found") 

        assert isinstance(self._sd.certificates[0], MasterListSignerCertificate)

    @property
    def signerCertificates(self):
        ''' Returns the list of Master List Signer certificates. '''
        return self._sd.certificates

    @property
    def cscaList(self) -> CscaList:
        ''' Returns list of CSCAs '''
        return self._sd.content

    def verify(self) -> NoReturn:
        ''' 
        Verifies every SignerInfo object and the digital signature over content.
        On verification failure a CscaMasterListError exception is risen.
        '''

        try:
            self._sd.verify()
        except SignedDataError as e:
            raise CscaMasterListError(str(e)) from e