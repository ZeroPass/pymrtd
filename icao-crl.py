from ldif3 import LDIFParser
from asn1crypto import crl, x509, pem
import re

from data.structure.DSC import CertX509
from data.structure.crl import CertificationRevocationList

certificateList = {}
revocationList = {}
parser = LDIFParser(open('C://Users/nejko/Desktop/ZeroPass/B1/random/parseCSCAandCRL/data/icaopkd-001-dsccrl-003749.ldif', 'rb'))
for dn, entry in parser.parse():
    if 'userCertificate;binary' in entry:
        countryCode = re.findall(r'[c,C]{1}=(.*)(,dc=data){1}', dn)[0][0]
        cert = x509.Certificate.load(*entry['userCertificate;binary'])
        gege = CertX509(cert)
        if countryCode not in certificateList:
            certificateList[countryCode] = {}
        certificateList[countryCode][cert.serial_number] = cert

    if 'certificateRevocationList;binary' in entry:
        countryCode = re.findall(r'[c,C]{1}=(.*)(,dc=data){1}', dn)[0][0]
        ##revocationList[countryCode] = x509.load_der_x509_crl(*entry['certificateRevocationList;binary'], default_backend())
        revocationList[countryCode] = crl.CertificateList.load(*entry['certificateRevocationList;binary'])
        gege = CertificationRevocationList(revocationList[countryCode])
        ##print("country:" + countryCode
        ##      + ",created: " + revocationList[countryCode].last_update.strftime("%Y-%m-%d %H:%M")
        ##      + ",next: " + revocationList[countryCode].next_update.strftime("%Y-%m-%d %H:%M")
        ##      + (" ***out of date : " + str(present - revocationList[countryCode].next_update) if revocationList[countryCode].next_update < present else ""))

        f = 8
        #fh = open("./data/CAN.crl", "wb")
        #fh.write(*entry['certificateRevocationList;binary'])
        #fh.close()
