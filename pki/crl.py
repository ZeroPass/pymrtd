'''
    File name: crl.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy import create_engine
from structure.storageManager import Connection
from asn1crypto import x509, crl
from asn1crypto.crl import CertificateList
from settings import *
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
    -signiture algorithm string**
    -signature hash algorithm string**
    -SHA256 hash over whole object string or bytes
"""

class CertificationRevocationListError(Exception):
    pass

class SignatureAlgorithm(enum.Enum):
    Alg1 = 1
    Alg2 = 2
    Alg3 = 3

class CertificationRevocationList(CertificateList):
    """Class; object that stores Certificate Revocation List (CRL) and has supporting functions"""
    __tablename__ = 'CertificationRevocationList'

    crlObj = None #Column(String)
    hashOfCrlObj = Column(String)
    countryName = Column(String, primary_key=True)
    size = Column(Integer)
    validStart = Column(DateTime)
    validEnd = Column(DateTime)
    signatureAlgorithm = Column(String)
    signatureHashAlgorithm = Column(String)

    def __init__(self, crl: crl):
        """With initialization crl needs to be provided"""
        self.crlObj = crl
        self.hashOfCrlObj = self.calculateHashOfObj(crl)
        self.countryName = crl.issuer.native['country_name']
        self.size = len(crl['tbs_cert_list']['revoked_certificates'])
        self.validStart = crl['tbs_cert_list']['this_update']
        self.validEnd = crl['tbs_cert_list']['next_update']
        self.signatureAlgorithm = crl['tbs_cert_list']['signature']['algorithm']
        self.signatureHashAlgorithm = self.calculateHashOfSignatureAlgorithm(crl['tbs_cert_list']['signature']['algorithm'])


    def calculateHashOfObj(self, obj: crl) -> str:
        """Calculate SHA256 hash of whole CRL object"""
        logger.info("Calculated value of CRL object")
        return "TODO; calculate hash"

    def calculateHashOfSignatureAlgorithm(self, signatureAlgorithm: str) -> str:
        """Calculate hash of signature algorithm"""
        logger.info("Calculated value of signature algorithm")
        return "TODO; calculate hash"

    def verify(self, issuer: x509.Certificate) ->bool:
        """Verify CRL"""

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

    def validStart(self) -> datetime:
        """In certificate the field is 'this_update'"""
        logger.info("CRL has been created: " + self.validStart)
        return self.validStart

    def validEnd(self) -> datetime:
        """In certificate the field is 'next_update'"""
        logger.info("CRL will be expired: " + self.validEnd)
        return self.validEnd

    def signatureAlgorithm(self) -> str:
        """It returns signature algorithm"""
        logger.info("Signature algorithm: " + self.signatureAlgorithm)
        return self.signatureAlgorithm

    def signatureHashAlgorithm(self) -> str:
        """It returns hash of signature algorithm"""
        logger.info("Signature hash algorithm: " + self.signatureHashAlgorithm)
        return self.signatureHashAlgorithm

    def hashOfCRLobj(self) -> str:
        """SHA256 hash over CRL object"""
        logger.info("Hash of CRL object: " + self.hashOfCrlObj)
        return self.hashOfCrlObj


#
#Storage management functions
#
def write(crl: CertificationRevocationList, connection: Connection):
    """Write to database with ORM"""
    try:
        logger.info("Writing CRL object to database. Country:" + crl.countryName())
        connection.getSession().add(crl)
        connection.getSession().commit()
    except Exception as e:
        raise CertificationRevocationListError("Problem with writing the object")

def read(countryName: str, connection: Connection):
    """Reading from database"""
    try:
        logger.info("Reading CRL object from database. Country:" + countryName)
        connection.getSession().query(CertificationRevocationList).count()
        r = 8
    except Exception as e:
        raise CertificationRevocationListError("Problem with writing the object")
