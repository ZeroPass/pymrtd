import asn1crypto.core as asn1
from asn1crypto.algos import DigestAlgorithm
from asn1crypto import cms
from asn1crypto.util import int_from_bytes

from .base import ElementaryFile, LDSVersionInfo
from .dg import DataGroup, DataGroupNumber
from pymrtd.pki import x509, algo_utils
from pymrtd.pki.cms import SignedData, SignedDataError

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from typing import List, NoReturn, Union



class LDSSecurityObjectVersion(asn1.Integer):
    _map = {
        0: 'v0',
        1: 'v1'
    }

    @property
    def value(self):
        return int_from_bytes(self.contents, signed=True)

class DataGroupHash(asn1.Sequence):
    _fields = [
        ('dataGroupNumber', DataGroupNumber),
        ('dataGroupHashValue', asn1.OctetString),
    ]

    @property
    def number(self) -> DataGroupNumber:
        return self['dataGroupNumber']

    @property
    def hash(self) -> bytes:
        return self['dataGroupHashValue'].native

class DataGroupHashValues(asn1.SequenceOf):
    _child_spec = DataGroupHash

    def contains(self, dgNumber: DataGroupNumber) -> bool:
        assert isinstance(dgNumber, DataGroupNumber)
        for dg in self:
            if dg.number == dgNumber:
                return True
        return False

    def find(self, dgNumber: DataGroupNumber) -> Union[DataGroupHash, None]:
        assert isinstance(dgNumber, DataGroupNumber)
        for dg in self:
            if dg.number == dgNumber:
                return dg
        return None

    
class LDSSecurityObject(asn1.Sequence):
    _fields = [
        ('version', LDSSecurityObjectVersion),
        ('hashAlgorithm', DigestAlgorithm),
        ('dataGroupHashValues', DataGroupHashValues),
        ('ldsVersionInfo', LDSVersionInfo, {'optional': True})
    ]

    @property
    def version(self) -> LDSSecurityObjectVersion:
        return self['version']

    @property
    def dgHashAlgo(self) -> DigestAlgorithm:
        ''' Returns the hash algorithm that the hash values of data groups were produced with. '''
        return self['hashAlgorithm']

    @property
    def dgHashes(self) -> DataGroupHashValues:
        ''' Returns hash values of data groups. '''
        return self['dataGroupHashValues']

    @property
    def ldsVerion(self) -> Union[LDSVersionInfo, None]:
        ''' Returns the version of LDS. It can return None if version of this object is 0 '''
        return self['ldsVersionInfo']

    def getDgHasher(self) -> hashes.Hash:
        ''' Returns hashes.Hash object of dgHashAlgo '''
        h = algo_utils.get_hash_algo_by_name(self.dgHashAlgo['algorithm'].native)
        return hashes.Hash(h, backend=default_backend())

    def find(self, dgNumber: DataGroupNumber) -> Union[DataGroupHash, None]:
        '''' 
        Returns DataGroupHash if DataGroupHashValues contains specific data group number, else None
        :param dgNumber:
            Data group number to find DataGroupHash object
        '''

        assert isinstance(dgNumber, DataGroupNumber)
        return self.dgHashes.find(dgNumber)

    def contains(self, dg: DataGroup) -> bool:
        '''' 
        Returns True if DataGroupHashValues data group with the same hash, else False
        :param dg:
            Data group to find and compare hash value of
        '''

        assert isinstance(dg, DataGroup)
        dgh = self.find(dg.number)
        if dgh is None:
            return False

        h = self.getDgHasher()
        h.update(dg.dump())
        return h.finalize() == dgh.hash



class SODError(Exception):
    pass

class SOD(ElementaryFile):
    cms.ContentType._map[id_mrtd_ldsSecurityObject.dotted] = 'ldsSecurityObject'
    cms.EncapsulatedContentInfo._oid_specs['ldsSecurityObject'] = LDSSecurityObject
    cms.ContentInfo._oid_specs['signed_data'] = SignedData

    SignedData._certificate_type = x509.DocumentSignerCertificate
    content_spec = cms.ContentInfo

    class_ = 1
    method = 1
    tag    = 23

    @classmethod
    def load(cls, encoded_bytes, strict=False):
        value = super().load(encoded_bytes, strict=strict)
        ci = value.content
        ctype = ci['content_type'].native
        if ctype != 'signed_data': # ICAO 9303-10-p21
            raise SODError("Invalid master list content type: {}, should be 'signed_data'".format(ctype))

        value._sd = ci['content']
        cver = value._sd.version.native
        if cver != 'v1' and cver != 'v3' and cver != 'v4': # RFC3369
            raise CscaMasterListError("Invalid SignedData version: {}".format(cver))

        if value._sd.contentType.dotted != oids.id_mrtd_ldsSecurityObject:
            raise SODError("Invalid encapContentInfo type: {}, should be {}".format(value._sd.contentType.dotted, oids.id_mrtd_ldsSecurityObject))

        if 1 < value.ldsSecurityObject.version.value < 0:
            raise SODError("Unsupported LDSSecurityObject version: {}, should be 0 or 1".format(seco.version))

        assert isinstance(value._sd.certificates[0], x509.DocumentSignerCertificate) if len(value._sd.certificates) else True
        return value

    @property
    def dsCertificates(self) -> Union[List[x509.DocumentSignerCertificate], None]:
        ''' Returns list of document signer certificates if present, otherwise None. '''
        return self._sd.certificates

    @property
    def ldsSecurityObject(self) -> LDSSecurityObject:
        return self._sd.content

    @property
    def signers(self) -> List[cms.SignerIdentifier]:
        ''' Returns list of signer identifiers which signed this document. '''
        sids = []
        for si in self._sd.signerInfos:
            sids.append(si['sid'])
        return sids

    def verify(self, issuer_cert: x509.DocumentSignerCertificate = None, nc_verification = False) -> NoReturn:
        ''' 
        Verifies every stored digital signature made over signed LdsSecurityObject.
        :raises: SODError - if verification fails or other error occurs.
        '''
        try:
            self._sd.verify(issuer_cert if issuer_cert is not None else [])
        except SignedDataError as e:
            raise SODError(str(e)) from e