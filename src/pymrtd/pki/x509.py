from asn1crypto import x509
from datetime import datetime
from typing import Optional, overload

from .oids import id_icao_cscaMasterListSigningKey #pylint: disable=relative-beyond-top-level
from .cert_utils import verify_cert_sig #pylint: disable=relative-beyond-top-level

class CertificateVerificationError(Exception):
    pass

class Certificate(x509.Certificate):
    @property
    def fingerprint(self) -> str:
        """SHA256 hash string of this object"""
        return self.sha256.hex()

    @property
    def issuerCountry(self) -> str:
        """Function returns country of certificate issuer"""
        country = self.issuer.native['country_name']
        return country

    @property
    def subjectKey(self) -> bytes:
        """Function returns subject key of certificate"""
        return self.key_identifier

    @property
    def authorityKey(self) -> bytes:
        """Function returns authority key of certificate"""
        return self.authority_key_identifier

    @property
    def notValidBefore(self) -> datetime:
        """
        Returns the date and time in Zulu (no time zone) on which the certificate validity period begins.
        """
        return self.not_valid_before.replace(tzinfo=None)

    @property
    def notValidAfter(self) -> datetime:
        """
        Returns the date and time in Zulu (no time zone) on which the certificate validity period begins.
        """
        return self.not_valid_after.replace(tzinfo=None)

    def isValidOn(self, dateTime: datetime):
        ''' Verifies if certificate is valid on specific date-time '''
        nvb = self.notValidBefore
        nva = self.notValidAfter
        dateTime = dateTime.replace(tzinfo=nvb.tzinfo)
        return nvb < dateTime < nva

    def checkConformance(self) -> None:
        """
        Verifies that this certificate conform to the basic X.509 standard.
        An exception is risen if conformance check fails.
        See methods _verify_cert_fields() and _verify_tbs_cert_fields()
        to get information what is checked.
        :raise: CertificateVerificationError if conformance check fails.
        """
        self._verify_cert_fields()
        self._verify_tbs_cert_fields()

    def verify(self, issuingCert: x509.Certificate, checkConformance = False) -> None:
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        :param issuingCert: The certificate that issued this certificate
        :param checkConformance: X.509 certificate conformance verification, if False only signature will be verified.
                                 Conformance verification can also be done through checkConformance method.
        :raises: CertificateVerificationError on failed signature verification or failed Conformance check.
        """

        # Verify certificate is conform to the basic X.509 standard
        if checkConformance:
            self.checkConformance()

        if not verify_cert_sig(self, issuingCert):
            raise CertificateVerificationError("Signature verification failed")

    @staticmethod
    def _require(cond, message: str):
        if not cond:
            raise CertificateVerificationError(message)

    def _require_cert_field(self, field: str):
        Certificate._require(field in self,
            "Missing required certificate field '{}'".format(field)
        )

    def _verify_cert_fields(self):
        self._require_cert_field('tbs_certificate')
        self._require_cert_field('signature_algorithm')
        self._require_cert_field('signature_value')

    def _require_tbs_cert_field(self, field: str):
        Certificate._require(field in self['tbs_certificate'],
            "Missing required tbs certificate field '{}'".format(field)
        )

    def _verify_tbs_cert_fields(self):
        self._require_tbs_cert_field('extensions')
        self._require_tbs_cert_field('issuer')
        self._require_tbs_cert_field('serial_number')
        self._require_tbs_cert_field('signature')
        self._require_tbs_cert_field('subject')
        self._require_tbs_cert_field('subject_public_key_info')
        self._require_tbs_cert_field('validity')
        self._require_tbs_cert_field('version')

        Certificate._require('country_name' in self.issuer.native,
            "Issuer field is missing field 'country_name'"
        )
        cn = self.issuer.native['country_name']
        Certificate._require( 0 < len(cn) < 3,
            'Invalid country name in issuer field: {}'.format(cn)
        )

        Certificate._require('country_name' in self.subject.native,
            "Subject field is missing field 'country_name'"
        )
        cn = self.subject.native['country_name']
        Certificate._require( 0 < len(cn) < 3,
            'Invalid country name in subject field: {}'.format(cn)
        )

    def _require_extension_field(self, field: str):
        exts = self['tbs_certificate']['extensions']
        for e in exts:
            if field in e['extn_id'].native:
                return
        Certificate._require(False,
            "Missing required extension field '{}'".format(field)
         )

    def _require_extension_value(self, field: str, value):
        exts = self['tbs_certificate']['extensions']
        for e in exts:
            if field in e['extn_id'].native:
                if e['extn_value'].native == value:
                    return
                Certificate._require(False,
                    "Extension value invalid! ext='{}' v='{}', req_v='{}'".format(field, e['extn_value'].native, value)
                )

        Certificate._require(False,
            "Missing required extension field '{}'".format(field)
        )


class CscaCertificate(Certificate):
    def checkConformance(self) -> None:
        """
        Verifies that this CSCA certificate conform to the basic X.509 and ICAO 9303 standard.
        See ICAO 9303 part 12, 7.1.1 Certificate Profile and Appendix B and C to the Part 12.
        https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf

        This method first verifies that CSCA conforms to the X.509 standard, see Certificate.checkConformance().
        Then verifies conformance to the ICAO 9303 standard:
            - requirement for the subject and issuer field to have the same country value.
            - requirement for the CSCA to be root CA certificate
            - requirement for the key usage value to contain keyCertSign and cRLSign.
            - requirement for the path length constraint value to be 0 or 1.
              Note: ICAO 9303 requires max path length to be 0 or 1 for LCSCA.
                    This implementation just check that the path length constraint
                    to be either of the 2 values but doesn't check for the cert type i.e. is it CSCA or LCSCA.
                    The reason for this is that not all CSCA/LCSCA follow this strictly.
                    Note, there are also certificate with greater value for the path length constraint.
                    Such certificate will be rejected by this function.
        :raise: CertificateVerificationError if conformance check fails.
        """
        # Check first conformance to the X.509 standard
        super().checkConformance()

        # Now verify CSCA conforms to the ICAO specifications
        Certificate._require(self.issuerCountry.lower() == self.subject.native['country_name'].lower(),
            "The subject and issuer country doesn't match"
        )

        super()._require_extension_field('basic_constraints')
        Certificate._require(self.ca == True, "Certificate is required to be root CA")
        Certificate._require(self.max_path_length is not None, "Missing 'PathLenConstraint' field in basic constraints")
        Certificate._require( self.max_path_length is None or 0 <= self.max_path_length <= 1, #Note: Portuguese cross-link CSCA has value 2
            "Invalid CSCA path length constraint: {}".format(self.max_path_length)
        )

        super()._require_extension_field('key_usage')
        key_usage = self.key_usage_value.native
        Certificate._require( 'key_cert_sign' in key_usage, "Missing field 'keyCertSign' in KeyUsage extension")
        Certificate._require('crl_sign' in key_usage, "Missing field 'cRLSign' in KeyUsage extension")

        super()._require_extension_field('key_identifier')
        Certificate._require(self.subjectKey is not None,
            "Missing required field 'subjectKeyIdentifier' in SubjectKeyIdentifier extension"
        )

    def verify(self, issuingCert: Optional[x509.Certificate] = None, checkConformance: bool = False):
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        :param issuingCert: (Optional) The certificate that issued this certificate.
                            If None, this certificate will be used as issuing certificate to verify the certificate signature.
        :param checkConformance: X.509 and ICAO 9303 CSCA conformance verification, if False only signature will be verified.
                                 Conformance verification can also be done through checkConformance method
        :raises: CertificateVerificationError on failed signature verification or failed Conformance check.
        """
        if issuingCert is None:
            issuingCert = self
        super().verify(issuingCert, checkConformance)


class MasterListSignerCertificate(Certificate):
    def checkConformance(self) -> None:
        """
        Verifies that this master list signer certificate conform to the basic X.509 and ICAO 9303 standard.
        See ICAO 9303 part 12, 7.1.1 Certificate Profile and Appendix B and C to the Part 12.
        https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf

        This method first verifies that certificate conforms to the X.509 standard, see Certificate.checkConformance().
        Then verifies conformance to the ICAO 9303 standard:
            - requirement for the subject and issuer field to have the same country value.
            - requirement for the key usage value to contain digitalSignature.
        :raise: CertificateVerificationError if conformance check fails.
        """
        # Check first conformance to the X.509 standard
        super().checkConformance()

        # Now verify master list signer certificate conforms to the ICAO specifications
        Certificate._require(self.issuerCountry.lower() == self.subject.native['country_name'].lower(),
            "The subject and issuer country doesn't match"
        )

        super()._require_extension_field('key_usage')
        key_usage = self.key_usage_value.native
        Certificate._require(
            'digital_signature' in key_usage,
            "Missing field 'digitalSignature' in KeyUsage"
        )

        #super()._require_extension_field('authority_key_identifier')
        #Certificate._require(self.authorityKey is not None, "Missing required field 'keyIdentifier' in AuthorityKeyIdentifier extension")

        # super()._require_extension_field('key_identifier')
        # Certificate._require(self.subjectKey is not None, "Missing required field 'subjectKeyIdentifier' in SubjectKeyIdentifier extension")

    def verify(self, issuingCert: x509.Certificate, checkConformance: bool = False):
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        :param issuingCert: The certificate that issued this certificate.
        :param checkConformance: X.509 and ICAO 9303 master list signer certificate conformance verification,
                                 if False only signature will be verified.
                                 Conformance verification can also be done through checkConformance method
        :raises: CertificateVerificationError on failed signature verification or failed Conformance check.
        """
        if self.ca: # Signer certificate is probably CSCA
                    # We do this check because not all master list issuers follow the specification rules and
                    # they use CSCA to sign master list instead of separate signer certificate issued by CSCA.
                    # See for example German master list no. 20190925)
            CscaCertificate.load(self.dump()).verify(issuingCert, checkConformance)
        else:
            super()._require_extension_value('extended_key_usage', [id_icao_cscaMasterListSigningKey]) #icao 9303-p12 p20, p27
            super().verify(issuingCert, checkConformance)

class DocumentSignerCertificate(Certificate):
    """ Document Signer Certificate (DSC) which should be used to verify SOD data file in eMRTD """

    def checkConformance(self) -> None:
        """
        Verifies that this DSC certificate conform to the basic X.509 and ICAO 9303 standard.
        See ICAO 9303 part 12, 7.1.1 Certificate Profile and Appendix B and C to the Part 12.
        https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf

        This method first verifies that DSC conforms to the X.509 standard, see Certificate.checkConformance().
        Then verifies conformance to the ICAO 9303 standard:
            - requirement for the subject and issuer field to have the same country value.
            - requirement for the key usage value to contain digitalSignature.
        :raise: CertificateVerificationError if conformance check fails.
        """
        # Check first DSC conformance to the X.509 standard
        super().checkConformance()

        # Now verify DSC conforms to the ICAO specifications
        Certificate._require(self.issuerCountry.lower() == self.subject.native['country_name'].lower(),
            "The subject and issuer country doesn't match"
        )

        super()._require_extension_field('key_usage')
        key_usage = self.key_usage_value.native
        Certificate._require(
            'digital_signature' in key_usage,
            "Missing field 'digitalSignature' in KeyUsage"
        )

        # super()._require_extension_field('authority_key_identifier')
        # Certificate._require(self.authorityKey is not None,
        #     "Missing required field 'keyIdentifier' in AuthorityKeyIdentifier extension"
        # )

        # super()._require_extension_field('key_identifier')
        # Certificate._require(self.subjectKey is not None,
        #     "Missing required field 'subjectKeyIdentifier' in SubjectKeyIdentifier extension"
        # )

    def verify(self, issuingCert: x509.Certificate, checkConformance: bool = False):
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        :param issuingCert: The certificate that issued this certificate.
        :param checkConformance: X.509 and ICAO 9303 DSC conformance verification, if False only signature will be verified.
                                 Conformance verification can also be done through checkConformance method
        :raises: CertificateVerificationError on failed signature verification or failed Conformance check.
        """
        super().verify(issuingCert, checkConformance)
