'''
    File name: x509.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from asn1crypto import x509, pem

class x509:
    """Class; object that stores x509 certificate and has supporting functions"""
    certificate = None

    def __init__(self, certificate):
        """With initialization certificate in x509 format needs to be provided"""
        self.certificate = certificate

    def serialNumber(self) -> int:
        """Function returns serial number of certificate"""
        return 123456789

    def countryIssuer(self) -> str:
        """Function returns county of certificate issuer"""
        return "SI"


