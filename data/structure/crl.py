'''
    File name: crl.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from asn1crypto import crl
from settings import *

class CertificationRevocationList:
    """Class; object that stores Certificate Revocation List (CRL) and has supporting functions"""
    crlObj = None
    countryName = None
    size = None

    def __init__(self, crl):
        """With initialization crl needs to be provided"""
        self.crlObj = crl
        self.countryName = crl.issuer.native['country_name']
        self.size = len(crl['tbs_cert_list']['revoked_certificates'])


    def countryName(self) -> str:
        """Function returns country of CRL issuer """
        logger.info("Getting country of CRL issuer: " + self.countryName)
        return self.countryName


    def size(self) -> int:
        """Function returns size of CRL"""
        logger.info("Getting size of CRL: " + self.size)
        return self.size

    def verification(self, certificateCSCA: str) -> bool:
        """Function that check if crl is signed by provided CSCA"""
        logger.info("Doing verification in CRL")
        return True

