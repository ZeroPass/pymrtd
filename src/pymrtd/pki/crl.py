import datetime
from .x509 import CscaCertificate #pylint: disable=relative-beyond-top-level
from .cert_utils import verify_sig #pylint: disable=relative-beyond-top-level
from asn1crypto.crl import CertificateList, RevokedCertificates
from typing import Optional

class CertificateRevocationListError(Exception):
    pass

class CertificateRevocationList(CertificateList):
    """Class; object that stores Certificate Revocation List (CRL) and has supporting functions """

    @property
    def issuerCountry(self) -> Optional[str]:
        """
        Function returns country of CRL issuer
        :return: Issuer country code. Note, can return None in non-conformant certificates.
        """
        country = None
        if self.issuer is not None and 'country_name' in self.issuer:
            country = self.issuer.native['country_name']
        return country

    @property
    def size(self) -> int:
        """Function returns size of CRL"""
        size = len(self['tbs_cert_list']['revoked_certificates'])
        return size

    @property
    def revokedCertificates(self) -> Optional[RevokedCertificates]:
        return self['tbs_cert_list']['revoked_certificates'] \
            if 'revoked_certificates' in self['tbs_cert_list'] \
            else None

    @property
    def thisUpdate(self) -> datetime:
        """Returns the date when this CRL was issued"""
        this_update = self['tbs_cert_list']['this_update'].native
        return this_update.replace(tzinfo=None)

    @property
    def nextUpdate(self) -> datetime:
        """Returns the date of next CRL issuance"""
        next_update = self['tbs_cert_list']['next_update'].native
        return next_update.replace(tzinfo=None)


    @property
    def signatureAlgorithm(self) -> str:
        """It returns signature algorithm"""
        sig_algo = self['signature_algorithm'].signature_algo
        return sig_algo

    @property
    def signatureHashAlgorithm(self) -> str:
        """It returns hash of signature algorithm"""
        hash_algo = self['signature_algorithm'].hash_algo
        return hash_algo

    @property
    def fingerprint(self) -> str:
        """SHA256 hash over this CRL object"""
        fp = self.sha256.hex()
        return fp

    def verify(self, issuer: CscaCertificate):
        """ Function verifies if crl is signed by provided issuer CSCA """
        verify_sig(issuer, self['tbs_cert_list'].dump(), self['signature'], self['signature_algorithm'])
