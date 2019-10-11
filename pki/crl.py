'''
    File name: crl.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from sqlalchemy import Column, Integer, String, MetaData, Table, DateTime
from sqlalchemy.orm import mapper

from .x509 import CscaCertificate
from pymrtd.settings import *
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()
from datetime import  datetime

from asn1crypto.crl import CertificateList

from sqlalchemy import inspect

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

class CertificateRevocationListError(Exception):
    pass

class CertificateRevocationList(CertificateList):
    """Class; object that stores Certificate Revocation List (CRL) and has supporting functions"""
    #__tablename__ = 'CertificationRevocationList'
    #id = None
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


    @property
    def issuerCountry(self) -> str:
        """Function returns country of CRL issuer """
        country = self.issuer.native['country_name']
        logger.debug("Getting country of CRL issuer: " + country)
        return country

    @property
    def size(self) -> int:
        """Function returns size of CRL"""
        size = len(self['tbs_cert_list']['revoked_certificates'])
        logger.debug("Getting size of CRL: " + str(size))
        return size

    @property
    def thisUpdate(self) -> datetime:
        """In certificate the field is 'this_update'"""
        this_update = self['tbs_cert_list']['this_update'].native
        logger.debug("CRL has been created on: " + str(this_update))
        return this_update

    @property
    def nextUpdate(self) -> datetime:
        """In certificate the field is 'next_update'"""
        next_update = self['tbs_cert_list']['next_update'].native
        logger.debug("Next CRL update: " + str(next_update))
        return next_update

    @property
    def signatureAlgorithm(self) -> str:
        """It returns signature algorithm"""
        sig_algo = self['signature_algorithm'].signature_algo
        logger.debug("Signature algorithm: " + sig_algo)
        return sig_algo

    @property
    def signatureHashAlgorithm(self) -> str:
        """It returns hash of signature algorithm"""
        hash_algo = self['signature_algorithm'].hash_algo
        logger.debug("Signature hash algorithm: " + hash_algo)
        return hash_algo

    @property
    def fingerprint(self) -> str:
        """SHA256 hash over CRL object"""
        fp = self.sha256.hex()
        logger.debug("Fingerprint of CRL object: " + fp)
        return fp

    def calculateHashOfSignatureAlgorithm(self, signatureAlgorithm: CscaCertificate) -> str:
        """Calculate hash of signature algorithm"""
        logger.debug("Calculated value of signature algorithm")
        raise NotImplementedError()

    def verify(self, issuer: CscaCertificate) ->bool:
        """Function that check if crl is signed by provided CSCA"""
        raise NotImplementedError()

class CertificateRevocationListStorage(object):
    """Class for interaaction between code structure and database"""
    _object = None
    _issuerCountry = None
    _size = None
    _thisUpdate = None
    _nextUpdate = None
    _signatureAlgorithm = None
    _signatureHashAlgorithm = None
    _fingerprint = None

    def __init__(self, crl: CertificateRevocationList):
        """Initialization class with serialization of CRL"""
        self.size = crl.size
        self.issuerCountry = crl.issuerCountry
        self.thisUpdate = crl.thisUpdate
        self.nextUpdate = crl.nextUpdate
        self.signatureAlgorithm = crl.signatureAlgorithm
        self.signatureHashAlgorithm = crl.signatureHashAlgorithm
        self.serializeCRL(crl)

    def serializeCRL(self, crl: CertificateRevocationList):
        """Function serialize CRL object to sequence"""
        self.object = crl.dump()

    def getObject(self) -> CertificateRevocationList:
        """Returns crl object"""
        return CertificateRevocationList.load(self.object)


"""
Column('id', Integer, primary_key=True),
                            Column('issuerCountry', String),
                            Column('size', Integer),
                            Column('validStart', DateTime),
                            Column('validEnd', DateTime),
                            Column('signatureAlgorithm', String),
                            Column('signatureHashAlgorithm', String)
                            )
                            """

#
#Storage management functions
#
from pymrtd.data.storage.storageManager import Connection

def writeToDB_CRL(crl: CertificateRevocationList, connection: Connection):
    """Write to database with ORM"""
    try:
        logger.info("Writing CRL object to database. Country: " + crl.issuerCountry)
        crls = CertificateRevocationListStorage(crl)
        connection.getSession().add(crls)
        connection.getSession().commit()

    except Exception as e:
        raise CertificateRevocationListError("Problem with writing the object")

def readFromDB_CRL(issuerCountry: str, connection: Connection) -> CertificateRevocationList:
    """Reading from database"""
    try:
        logger.info("Reading CRL object from database. Country:" + issuerCountry)
        connection.getSession().query(CertificateRevocationListStorage).count()
        ter = connection.getSession().query(CertificateRevocationListStorage).all()[connection.getSession().query(CertificateRevocationListStorage).count()-1]
        ter1 = ter.getObject()

    except Exception as e:
        raise CertificateRevocationListError("Problem with writing the object")

