'''
    File name: x509.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from asn1crypto import x509, pem
from settings import *

class CertX509:
    """Class; object that stores x509 certificate and has supporting functions"""
    certificate = None
    county = None
    serialNumber = None
    subjectKey = None
    authorityKey = None

    def __init__(self, certificate):
        """With initialization certificate in x509 format needs to be provided"""
        self.certificate = certificate
        self.serialNumber = certificate.serial_number
        self.authorityKey = certificate.authority_key_identifier
        self.subjectKey = certificate.authority_key_identifier #temporary

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

