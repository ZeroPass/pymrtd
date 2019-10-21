'''
    File name: crl.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy import create_engine

from .x509 import CscaCertificate
from .cert_utils import verify_sig
from pymrtd.data.storage.storageManager import Connection
from pymrtd.settings import *

from asn1crypto.crl import CertificateList

import datetime
import enum
import pickle

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

class CertificationRevocationListError(Exception):
    pass

#class SignatureAlgorithm(enum.Enum):
#    Alg1 = 1
#    Alg2 = 2
#    Alg3 = 3

class CertificateRevocationList(CertificateList):
    """Class; object that stores Certificate Revocation List (CRL) and has supporting functions"""
    #__tablename__ = 'CertificationRevocationList'

    #crlObj = None #Column(String)
    #hashOfCrlObj = Column(String)
    #countryName = Column(String, primary_key=True)
    #size = Column(Integer)
    #validStart = Column(DateTime)
    #validEnd = Column(DateTime)
    #signatureAlgorithm = Column(String)
    #signatureHashAlgorithm = Column(String)

    #def __init__(self, crl: crl):
    #    """With initialization crl needs to be provided"""
    #    self.crlObj = crl
    #    self.hashOfCrlObj = self.calculateHashOfObj(crl)
    #    self.countryName = crl.issuer.native['country_name']
    #    self.size = len(crl['tbs_cert_list']['revoked_certificates'])
    #    self.validStart = crl['tbs_cert_list']['this_update']
    #    self.validEnd = crl['tbs_cert_list']['next_update']
    #    self.signatureAlgorithm = crl['tbs_cert_list']['signature']['algorithm']
    #    self.signatureHashAlgorithm = self.calculateHashOfSignatureAlgorithm(crl['tbs_cert_list']['signature']['algorithm'])


    #def calculateHashOfSignatureAlgorithm(self, signatureAlgorithm: CscaCertificate) -> str:
    #    """Calculate hash of signature algorithm"""
    #    logger.debug("Calculated value of signature algorithm")
    #    raise NotImplementedError()

    def verify(self, issuer: CscaCertificate):
        """Function verifies if crl is signed by provided issuer CSCA"""
        verify_sig(issuer, self['tbs_cert_list'].dump(), self['signature'], self['signature_algorithm'])
        

    @property
    def issuerCountry(self) -> str:
        """Function returns country of CRL issuer"""
        country = self.issuer.native['country_name']
        return country

    @property
    def size(self) -> int:
        """Function returns size of CRL"""
        size = len(self['tbs_cert_list']['revoked_certificates'])
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


#
#Storage management functions
#
def write(crl: CertificateRevocationList, connection: Connection):
    """Write to database with ORM"""
    try:
        logger.info("Writing CRL object to database. Country:" + crl.countryName())
        connection.getSession().add(crl)
        connection.getSession().commit()
    except Exception as e:
        raise CertificationRevocationListError("Problem with writing the object")

def readFromDB(countryName: str, connection: Connection):
    """Reading from database"""
    try:
        logger.info("Reading CRL object from database. Country:" + countryName)
        connection.getSession().query(CertificationRevocationList).count()
        r = 8
    except Exception as e:
        raise CertificationRevocationListError("Problem with writing the object")
