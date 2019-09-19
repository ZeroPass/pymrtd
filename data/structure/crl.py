'''
    File name: crl.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from asn1crypto import crl

class CertificationRevocationList:
    """Class; object that stores Certificate Revocation List (CRL) and has supporting functions"""
    crlObj = None

    def __init__(self, crl):
        """With initialization crl needs to be provided"""
        self.crlObj = crl

    def size(self) -> int:
        """Function returns size of CRL"""
        return 1

    def verification(self, certificateCSCA: str) -> bool:
        """Function that check if crl is signed by provided CSCA"""
        return True

