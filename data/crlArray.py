'''
    File name: crlArray.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from pki.crl import CertificationRevocationList
from settings import *


class CRLArray:
    """Class: array of CRL(arrays)"""

    dict = {}

    def __init__(self, crl):
        item = CertificationRevocationList(crl)
        #add to dictonary with key 'countryName'
        dict[item.countryName] = item

    def getCountry(self, countryName) -> CertificationRevocationList:
        """Function returns country of CRL issuer """
        foundItem = self.dict[countryName] if countryName in self.dict else None
        logger.info("Getting country with countryName: " + countryName + ", found/not found" + True if foundItem is not None else False)
        return foundItem


