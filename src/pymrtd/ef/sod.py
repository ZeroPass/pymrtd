import asn1crypto.core as asn1
from asn1crypto.algos import DigestAlgorithm
from asn1crypto.util import int_from_bytes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from pymrtd.pki import algo_utils, cms, oids, x509
from typing import cast, List, Optional, Union

from .base import ElementaryFile, LDSVersionInfo
from .dg import DataGroup, DataGroupNumber

class SODError(Exception):
    pass

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
    def ldsVersion(self) -> Union[LDSVersionInfo, None]:
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
        Returns True if DataGroupHashValues has matching hash of data group, else False
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


class _DataChoice(asn1.Choice): # For OID '1.2.840.113549.1.7.1'
    _alternatives = [
        ('data', asn1.OctetString),
        ('ldsSecurityObject', LDSSecurityObject),
    ]

class SODSignedData(cms.MrtdSignedData):
    _certificate_spec = x509.DocumentSignerCertificate
    cms.cms_register_encap_content_info_type(
        'ldsSecurityObject',
        oids.id_mrtd_ldsSecurityObject,
        LDSSecurityObject
    )
    cms.cms_register_encap_content_info_type(
        'data',
        oids.id_data,
        _DataChoice
    )

    @property
    def content(self) -> LDSSecurityObject:
        ''' overloads MrtdSignedData.content '''
        lso = super().content
        if isinstance(lso, _DataChoice): # In case of OID '1.2.840.113549.1.7.1'
            lso = lso.chosen
        if not isinstance(lso, LDSSecurityObject):
            raise SODError('SignedData content is not not LDSSecurityObject')
        return lso


class SODContentInfo(cms.MrtdContentInfo):
    _signed_data_spec = SODSignedData

class SOD(ElementaryFile):

    class_ = 1
    method = 1
    tag    = 23

    _content_spec = SODContentInfo

    _allowedSodContentTypes = {
        oids.id_data, # Some Chinese passports has this OID instead of id_mrtd_ldsSecurityObject
    }

    @classmethod
    def load(cls, encoded_data: bytes, strict=False) -> "SOD":
        '''
        Loads EF.SOD from BER/DER-encoded byte string
        :param encoded_data:
            A byte string of BER or DER encoded data
        :param strict:
            A boolean indicating if trailing data should be forbidden - if so, a
            `SODError` will be raised when content type of SignedData is not 2.23.136.1.1.1 or trailing data exists.
        :return:
            A instance of the `SOD`
        :raises:
            SODError - when an error occurs while parsing `encoded_data`.
        '''
        try:
            # Parse parent type
            s = cast(cls, super(SOD, cls).load(encoded_data, strict=strict))
            assert isinstance(s, SOD)

            ci = s.content
            ctype = ci['content_type'].native
            if ctype != 'signed_data': # ICAO 9303-10-p21
                raise SODError(f"Invalid content type: '{ctype}', expected 'signed_data'")

            sdver = s.signedData.version.native
            if sdver != 'v3': # ICAO 9303 part 10 - 4.6.2.2
                raise SODError(f'Invalid SignedData version: {sdver}')

            if not cls._valid_content_type(s.signedData.contentType, strict): #s.signedData.contentType.dotted != oids.id_mrtd_ldsSecurityObject:
                raise SODError(f'Invalid encapContentInfo type: {s.signedData.contentType.dotted}, expected {oids.id_mrtd_ldsSecurityObject}')

            if not(0 <= s.ldsSecurityObject.version.value <= 1):
                raise SODError(f'Unsupported LDSSecurityObject version: {s.ldsSecurityObject.version.value}, expected 0 or 1')

            assert isinstance(s.signedData.certificates[0], x509.DocumentSignerCertificate) if len(s.signedData.certificates) else True
            assert isinstance(s.signedData.content, LDSSecurityObject)
            return s
        except SODError: raise
        except AssertionError: raise
        except Exception as e:
            raise SODError(e)

    def dump(self, force=False):
        """
        Encodes the value using DER

        :param force:
            If the encoded contents already exist, clear them and regenerate
            to ensure they are in DER format instead of BER format

        :return:
            A byte string of the DER-encoded value
        """
        self.contents = self.content.dump(force)
        return super().dump(force)

    @classmethod
    def _valid_content_type(cls, ct, strict):
        oid = ct.dotted
        return oid == oids.id_mrtd_ldsSecurityObject or \
            (strict == False and oid in cls._allowedSodContentTypes)

    def __str__(self):
        """
        Returns string representation of self i.e. EF.SOD(fp=XXXXXXXXXXXXXXXX)
        """
        if self._str_rep is None:
            self._str_rep = super().__str__()\
                .replace("EF(", "EF.SOD(", 1)
        return self._str_rep

    @property
    def signedData(self) -> SODSignedData:
        return self.content['content']

    @property
    def ldsSecurityObject(self) -> LDSSecurityObject:
        return self.signedData.content

    @property
    def dscCertificates(self) -> Optional[List[x509.DocumentSignerCertificate]]:
        ''' Returns list of document signer certificates if present, otherwise None. '''
        return self.signedData.certificates

    def getDscCertificate(self, si: cms.SignerInfo) -> Optional[x509.DocumentSignerCertificate]:
        '''
        Returns document signer certificates from the list of `dscCertificates` which signed `si` object.
        :param si: Signer object for which to return DSC certificate.
        :return: x509.DocumentSignerCertificate object or None if DSC is not found.
        :raises SODError: If `si` object is not version v1 or v3
        '''
        try:
            return self.signedData.getCertificate(si)
        except Exception as e:
            raise SODError(e) from e

    @property
    def signers(self) -> cms.SignerInfos:
        ''' Returns list of SignerInfo which signed this file. '''
        return self.signedData.signers

    def verify(self, si: cms.SignerInfo, dsc: x509.DocumentSignerCertificate) -> None:
        '''
        Verifies LdsSecurityObject was signed by `dsc`.
        :param si: The signer info object of `dsc` certificate.
        :param dsc: The DSC certificate which issued this EF.SOD.
        :raises: SODError - if verification fails or other some error occurs.
        '''
        try:
            self.signedData.verify(si, dsc)
        except cms.MrtdSignedDataError as e:
            raise SODError(e) from e
