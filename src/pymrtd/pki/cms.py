from asn1crypto import algos, cms
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from pymrtd.pki import algo_utils, cert_utils, x509
from typing import List, Optional, Union


def cms_register_content_type(name, oid):
    cms.ContentType._map[oid] = name #pylint: disable=protected-access

def cms_register_encap_content_info_type(name, oid, type): #pylint: disable=redefined-builtin
    cms_register_content_type(name, oid)
    cms.EncapsulatedContentInfo._oid_specs[name] = type #pylint: disable=protected-access

class SignerInfoError(Exception):
    pass

class SignerInfo(cms.SignerInfo):
    _signed_digiest = None
    _content_type = None
    _signing_time = None

    _id = None
    _str_rpr = None

    def __str__(self):
        if self._str_rpr is None:
            sid = self.id
            if isinstance(sid, cms.IssuerAndSerialNumber):
                self._str_rpr = \
                    f"issuer='{sid['issuer'].human_friendly}', serial={hex(sid['serial_number'].native).replace('0x', '')}"
            elif self.version == 'v3':
                self._str_rpr = self.sid.native.hex()
            else:
                self._str_rpr = self.sid.native
        return self._str_rpr

    @property
    def id(self) -> Optional[Union[cms.IssuerAndSerialNumber, bytes]]:
        """
        Returns signer certificate identifier in form of 'issuer and serial number'
        or certificate subject key identifier.
        :return: Signer certificate identifier or None if `version` is not v1 or v3
        """
        if self._id is None:
            if self.version.native == 'v1': # IssuerAndSerialNumber
                self._id = self.sid.chosen
            elif self.version.native == 'v3': # keyid
                self._id =  self.sid.native
        return self._id

    @property
    def sid(self) -> cms.SignerIdentifier:
        """Returns SignerIdentifier object"""
        return self['sid']

    @property
    def version(self) -> cms.CMSVersion:
        return self['version']

    @property
    def signingTime(self) -> Optional[datetime]:
        """
        Returns signing date and time from signed attributes.
        :return: datetime object or None if signing time attribute is not present
        """
        if self._signing_time is None:
            for a in (self.signedAttributes or []):
                if a['type'].native == 'signing_time':
                    self._signing_time = a['values'][0].native
        return self._signing_time

    @property
    def signedDigest(self) -> Optional[bytes]:
        """
        Returns digest of content from signed attributes.
        :return: content digest or None if content digest is not present.
        """
        if self._signed_digiest is None:
            for a in (self.signedAttributes or []):
                if a['type'].native == 'message_digest':
                    self._signed_digiest = a['values'][0].native
        return self._signed_digiest

    @property
    def contentType(self):
        """
        Returns from signed attributes the type of the content of which digest is returned by `signedDigest`.
        :return: content type or None if content type is not present.
        """
        if self._content_type is None:
            for a in (self.signedAttributes or []):
                if a['type'].native == 'content_type':
                    self._content_type = a['values'][0]
        return self._content_type

    @property
    def contentHasher(self) -> hashes.Hash:
        ''' Returns hash object of digest algorithm for hashing content'''
        hash_algo = self['digest_algorithm']['algorithm'].native
        h = algo_utils.get_hash_algo_by_name(hash_algo)
        return hashes.Hash(h, backend=default_backend())

    @property
    def signature(self) -> bytes:
        return self['signature'].native

    @property
    def signedAttributes(self) -> Optional[cms.CMSAttributes]:
        return self['signed_attrs'] if 'signed_attrs' in self else None

    @property
    def signatureAlgorithm(self) -> algos.SignedDigestAlgorithm:
        ''' Returns signature algoritem '''
        hash_algo = self['digest_algorithm']['algorithm'].native
        sig_algo  = self['signature_algorithm']
        return algo_utils.update_sig_algo_if_no_hash_algo(sig_algo, hash_algo)

    def verifySignedAttributes(self, signerCert: x509.Certificate ) -> None:
        """
        Verifies signature made over `signed attributes`.
        :param signerCert: The certificate which signed the `signed attributes`.
        :raises SignerInfoError: If this doesn't contain `signed attributes` or
                                 if the signing time is not within signerCert validity or
                                 if signature verification fails.
        """
        signedAttrs = self.signedAttributes
        if signedAttrs is None:
            raise SignerInfoError("Missing field 'signed_attrs' in signer infos")

        if self.signingTime is not None and not signerCert.isValidOn(self.signingTime):
            raise SignerInfoError("Invalid signing time")

        # Make sure signedAttrs is asn1 SET type (DER tag 0x31)
        signedAttrs.tag    = 17
        signedAttrs.method = 1
        signedAttrs.class_ = 0

        signature = self.signature
        sig_algo  = self.signatureAlgorithm
        if not cert_utils.verify_sig(signerCert, signedAttrs.dump(force=True), signature, sig_algo):
            raise SignerInfoError("Signature verification failed")


class SignerInfos(cms.SignerInfos):
    _child_spec = SignerInfo


class MrtdSignedDataError(Exception):
    pass


class MrtdSignedData(cms.SignedData):
    _certificate_spec = x509.Certificate

    class CertificateSetOf(cms.CertificateSet):
        pass

    _fields = [
        *cms.SignedData._fields[0:3], # CMSVersion, digest_algorithms, encap_content_info
        ('certificates', CertificateSetOf, {'implicit': 0, 'optional': True}),
        cms.SignedData._fields[4], # crls
        ('signer_infos', SignerInfos)
    ]

    CertList = Union[List[_certificate_spec], CertificateSetOf]

    def __init__(self, value=None, default=None, **kwargs):
        self.CertificateSetOf._child_spec = self._certificate_spec #pylint: disable=protected-access
        super().__init__(value, default, **kwargs)

    @property
    def content(self):
        return self['encap_content_info']['content'].parsed

    @property
    def contentType(self):
        return self['encap_content_info']['content_type']

    @property
    def certificates(self) -> "CertList" :
        ''' Returns the list of certificates which signed signers info. '''
        return self['certificates']

    @property
    def digestAlgorithms(self) -> cms.DigestAlgorithms:
        return self['digest_algorithms']

    @property
    def signers(self) -> SignerInfos:
        ''' Returns SignerInfos object. '''
        return self['signer_infos']

    @property
    def version(self) -> cms.CMSVersion:
        return self['version']

    def getCertificate(self, si: SignerInfo) -> Optional[_certificate_spec]:
        """
        Returns Certificate from `self.certificates` which signed `si`.
        :param si: The signer info object for which to get the certificate.
        :return: _certificate_spec typed object if certificate is found, otherwise None
        :raises: MrtdSignedDataError if `si` version is not v1 or v3.
        """
        sid = si.id
        if isinstance(sid, cms.IssuerAndSerialNumber):
            return self.getCertificateBySNI(sid)
        if isinstance(sid, bytes):
            keyid = si.sid.native
            return self.getCertificateByKeyId(keyid)
        raise MrtdSignedDataError(f'Invalid SignerInfo version {si.version}')

    def getCertificateBySNI(self, sni: cms.IssuerAndSerialNumber) -> _certificate_spec:
        ''' Returns signer certificate identified by serial number and issuer '''
        return self.__class__._get_signer_cert_by_sni(self.certificates, sni) #pylint: disable=protected-access

    def getCertificateByKeyId(self, keyId: bytes)  -> _certificate_spec:
        ''' Returns signer certificate identified by subject key identifier '''
        return self.__class__._get_signer_cert_by_keyid(self.certificates, keyId) #pylint: disable=protected-access

    def verify(self, si: SignerInfo, issuerCert: x509.Certificate) -> None:
        '''
        Verifies the `issuerCert` signed this object.
        In essence, it verifies that signed hash from `si` object matches with the hash of `content` and
        that signed attributes of `si` object which include signed hash were signed by `issuerCert`.

        :param si: SignerInfo object of `issuerCert`.
        :param issuerCert: Signing certificate which signed `si`.
        :raises MrtdSignedDataError: When verifying `si` fails or when signed hash doesn't match with the hash of `content`.
        '''
        assert isinstance(si, SignerInfo)

        # 1.) Check signed content type is the same as this content type
        if si.contentType != self.contentType:
            raise MrtdSignedDataError("Signed content type doesn't match the actual content type")

        # 2.) Check si contains signed content hash
        if si.signedDigest is None:
            raise MrtdSignedDataError("Missing signed attribute 'message_digest'")

        # 3.) Verify signed hash matches with content hash
        h = si.contentHasher
        h.update(self.content.dump())
        if h.finalize() != si.signedDigest:
            raise MrtdSignedDataError("Content digest doesn't match signed digest")

        # 4.) Verify signature over signed attributes, which include signed content digest
        try:
            si.verifySignedAttributes(signerCert=issuerCert)
        except Exception as e:
            raise MrtdSignedDataError(e) from e

    @staticmethod
    def _get_signer_cert_by_sni(cert_list: CertList, sni: cms.IssuerAndSerialNumber):
        for c in cert_list:
            if c.serial_number == sni['serial_number'].native and c.issuer == sni['issuer']:
                return c
        return None

    @staticmethod
    def _get_signer_cert_by_keyid(cert_list: CertList, keyid: bytes):
        for c in cert_list:
            if c.key_identifier == keyid:
                return c
        return None


class MrtdContentInfo(cms.ContentInfo):
    _signed_data_spec = MrtdSignedData

    def __init__(self, value=None, default=None, **kwargs):
        self._oid_specs['signed_data'] = self._signed_data_spec
        super().__init__(value, default, **kwargs)
