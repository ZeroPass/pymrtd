'''
    File name: DSC.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from asn1crypto import x509, pem
from settings import *
from pki.x509 import Certificate, CertificateVerificationError
from pki.cert_utils import verify_cert_sig

class DSC(Certificate):
    """Class; object that stores x509 certificate and has supporting functions"""
    certificateObj = None
    county = None
    serialNumber = None
    subjectKey = None
    authorityKey = None

    def __init__(self, cert: x509.Certificate):
        """With initialization certificate in x509 format needs to be provided"""
        self.certificateObj = cert
        self.serialNumber = cert.serial_number
        self.authorityKey = cert.authority_key_identifier
        self.subjectKey = cert.authority_key_identifier #temporary

    def verify(self, issuing_cert: x509.Certificate):
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        On failure CertificateVerificationError exception is risen.
        """

        self._verifiy_cert_fields()
        self._verifiy_tbs_cert_fields()

        if not verify_cert_sig(self, issuing_cert):
            raise CertificateVerificationError("Signature verification failed")

    def countryIssuer(self) -> str:
        """Function returns county of certificate issuer"""
        logger.info("Getting 'Country issuer': " + self.county)
        return self.county

    def serialNumber(self) -> int:
        """Function returns serial number of certificate"""
        logger.info("Getting 'Serial numbe': " + self.serialNumber)
        return self.serialNumber

    def subjectKey(self) -> bytes:
        """Function returns subject key of certificate"""
        logger.info("Getting 'Subject key': " + self.subjectKey)
        return self.subjectKey if not None else None

    def authorityKey(self) -> bytes:
        """Function returns authority key of certificate"""
        logger.info("Getting 'Authority key': " + self.authorityKey)
        return self.authorityKey if not None else None

