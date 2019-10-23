'''
    File name: crl.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from .x509 import CscaCertificate
from .cert_utils import verify_sig

from asn1crypto.crl import CertificateList

import datetime

"""
CRL: \
    -object ***
    -serial Number***
    -subject key //not
    -authority key (CSCA - foreign key) ***
    -countrKey ***
    -start, end valid ***
    -signature algorithm string**
    -signature hash algorithm string**
    -SHA256 hash over whole object string or bytes
"""

class CertificateRevocationListError(Exception):
    pass

class CertificateRevocationList(CertificateList):
    """Class; object that stores Certificate Revocation List (CRL) and has supporting functions """

    @property
    def issuerCountry(self) -> str:
        """Function returns country of CRL issuer"""
        country = self.issuer.native['country_name']
        return country

    @property
    def size(self) -> int:
        """Function returns size of CRL"""
        size = len(self['tbs_cert_list']['revoked_certificates'])
        logger.debug("Getting size of CRL: " + str(size))
        return size

    @property
    def thisUpdate(self) -> datetime:
        """Returns the date when this CRL was issued"""
        this_update = self['tbs_cert_list']['this_update'].native
        return this_update

    @property
    def nextUpdate(self) -> datetime:
        """Returns the date of next CRL issuance"""
        next_update = self['tbs_cert_list']['next_update'].native
        return next_update

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