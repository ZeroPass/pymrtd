
import asn1crypto.core as asn1

from . import cms
from .x509 import CscaCertificate, MasterListSignerCertificate
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



class MlSignedData(cms.MrtdSignedData):
    _certificate_spec = MasterListSignerCertificate
    cms.cms_register_encap_content_info_type(
        'icaoCscaMasterList',
        id_icao_cscaMasterList, 
        CscaList
    )


class MlContentInfo(cms.MrtdContentInfo):
    _signed_data_spec = MlSignedData


class CscaMasterListError(Exception):
    pass


class CscaMasterList(MlContentInfo):

    @classmethod
    def load(cls, encoded_bytes, strict=False):
        ci = super().load(encoded_bytes, strict=strict)
        ctype = ci['content_type'].native
        if ctype != 'signed_data': # ICAO 9303-12-p25
            raise CscaMasterListError("Invalid master list content type: {}, should be 'signed_data'".format(ctype))

        ci._sd = ci['content']
        cver = ci._sd.version.native
        if cver != 'v3': # ICAO 9303-12-p25
            raise CscaMasterListError("Invalid SignedData version: {}, should be 'v3'".format(cver))

        if ci._sd.contentType.dotted != id_icao_cscaMasterList:
            raise CscaMasterListError("Invalid encapContentInfo type: {}, should be '{}'".format(ci._sd.contentType.dotted, id_icao_cscaMasterList))

        if ci._sd.content.version != 0: # ICAO 9303-12-p27
            raise CscaMasterListError("Unsupported encapContentInfo version: {}, should be 0".format(ci._sd.version))
        
        if len(ci._sd.certificates) < 1:
            raise CscaMasterListError("No master list signer certificate found") 

        assert isinstance(ci._sd.certificates[0], MasterListSignerCertificate)
        assert isinstance(ci._sd.content, CscaList)
        return ci

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
        except cms.MrtdSignedDataError as e:
            raise CscaMasterListError(str(e)) from e