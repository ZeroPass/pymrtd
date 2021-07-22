import datetime
from .x509 import CscaCertificate #pylint: disable=relative-beyond-top-level
from .cert_utils import verify_sig #pylint: disable=relative-beyond-top-level
from asn1crypto.crl import CertificateList, RevokedCertificates
from typing import Optional

class CertificateRevocationListError(Exception):
    pass

class CertificateRevocationList(CertificateList):
    """Class; object that stores Certificate Revocation List (CRL) and has supporting functions """

    @property
    def issuerCountry(self) -> Optional[str]:
        """
        Function returns country of CRL issuer
        :return: Issuer country code. Note, can return None in non-conformant certificates.
        """
        country = None
        if self.issuer is not None and 'country_name' in self.issuer.native:
            country = self.issuer.native['country_name']
        return country

    @property
    def size(self) -> int:
        """Function returns size of CRL"""
        size = len(self['tbs_cert_list']['revoked_certificates'])
        return size

    @property
    def revokedCertificates(self) -> Optional[RevokedCertificates]:
        return self['tbs_cert_list']['revoked_certificates'] \
            if 'revoked_certificates' in self['tbs_cert_list'] \
            else None

    @property
    def thisUpdate(self) -> datetime:
        """Returns the date when this CRL was issued"""
        this_update = self['tbs_cert_list']['this_update'].native
        return this_update.replace(tzinfo=None)

    @property
    def nextUpdate(self) -> datetime:
        """Returns the date of next CRL issuance"""
        next_update = self['tbs_cert_list']['next_update'].native
        return next_update.replace(tzinfo=None)

    @property
    def authorityKey(self) -> bytes:
        """Returns authority key of CRL issuer"""
        return self.authority_key_identifier

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

    def checkConformance(self) -> None:
        """
        Verifies that this CRL conform to ICAO 9303 part 12, section 7.1.4 doc.
        An exception is risen if conformance check fails.
        :raises CertificateRevocationListError: If conformance check fails.
        """
        self._require_crl_field('tbs_cert_list')
        self._require_crl_field('signature_algorithm')
        self._require_crl_field('signature')

        self._require_crl_tbs_cert_list_field('issuer')
        self._require_crl_tbs_cert_list_field('this_update')
        self._require_crl_tbs_cert_list_field('next_update')
        self._require_crl_tbs_cert_list_field('signature')

        CertificateRevocationList._require('country_name' in self.issuer.native, # ICAO 9303 part 12 section 7.1.1.1.1
            "Issuer field is missing field 'country_name'"
        )
        cn = self.issuer.native['country_name']
        CertificateRevocationList._require( len(cn) == 2, # ICAO 9303 part 12 section 7.1.1.1.1
            "Invalid country name in issuer field: {}".format(cn)
        )

        # Check crl number
        CertificateRevocationList._require( self.crl_number_value is not None,
            "Missing extension 'cRLNumber' "
        )
        CertificateRevocationList._require( self.crl_number_value.native >= 0,
            "CRL number is negative"
        )

        CertificateRevocationList._require( self.delta_crl_indicator_value is None,
            "CRL is delta"
        )

    def verify(self, issuerCert: CscaCertificate, checkConformance = False) -> None:
        """
        Function verifies if CRL is signed by provided issuer CSCA.
        :param issuerCert: The CSCA certificate which issued this CRL.
        :param checkConformance: If true conformance check is performed prior to signature verification.
        :raises CertificateRevocationListError: If conformance check fails or signature verification fails.
        :raises *Exception: If there was a problem in the process before signature is fully verified.
             See cert_utils.verify_sig
        """
        if checkConformance:
            self.checkConformance()

        if not verify_sig(issuerCert, self['tbs_cert_list'].dump(), self['signature'], self['signature_algorithm']):
            raise CertificateRevocationListError("Signature verification failed")

    @staticmethod
    def _require(cond, message: str):
        if not cond:
            raise CertificateRevocationListError(message)

    def _require_crl_field(self, field: str):
        CertificateRevocationList._require(field in self,
            "Missing required certificate field '{}'".format(field)
        )

    def _require_crl_tbs_cert_list_field(self, field: str):
        CertificateRevocationList._require(field in self['tbs_cert_list'],
            "Missing required certificate field '{}'".format(field)
        )
