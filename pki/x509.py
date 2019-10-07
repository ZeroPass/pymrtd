from asn1crypto import x509
from .cert_utils import verify_cert_sig
from datetime import datetime

class CertificateVerificationError(Exception):
    pass

class Certificate(x509.Certificate):
    @property
    def fingerprint(self) -> str:
        """SHA256 hash string of this object"""
        return self.sha256.hex()

    @property
    def issuerCountry(self) -> str:
        """Function returns county of certificate issuer"""
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

    def isValidOn(self, dateTime: datetime):
        ''' Verifies if certificate is valid on specific date-time '''
        nvb = self['tbs_certificate']['validity']['not_before'].native
        nva = self['tbs_certificate']['validity']['not_after'].native
        dateTime = dateTime.replace(tzinfo=nvb.tzinfo)
        return nvb < dateTime < nva

    def verify(self, issuing_cert: x509.Certificate, nc_verify = False):
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        On failure CertificateVerificationError exception is risen.

        :param issuing_cert: The certificate that issued this certificate
        :param nc_verify: Non-conformant verification, If True only signature will be verified.
        """

        # Verify certificate is conform to the ICAO specifications 
        if not nc_verify:
            self._verifiy_cert_fields()
            self._verifiy_tbs_cert_fields()

        if not verify_cert_sig(self, issuing_cert):
            raise CertificateVerificationError("Signature verification failed")

    def _require(cond, message: str):
        if not cond:
            raise CertificateVerificationError(message)

    def _require_cert_field(self, field: str):
        Certificate._require(field in self, 
            "Missing required certificate field '{}'".format(field)
         )

    def _verifiy_cert_fields(self):
        self._require_cert_field('tbs_certificate')
        self._require_cert_field('signature_algorithm')
        self._require_cert_field('signature_value')

    def _require_tbs_cert_field(self, field: str):
        Certificate._require(field in self['tbs_certificate'], 
            "Missing required tbs certificate field '{}'".format(field)
         )

    def _verifiy_tbs_cert_fields(self):
        self._require_tbs_cert_field('extensions')
        self._require_tbs_cert_field('issuer')
        self._require_tbs_cert_field('serial_number')
        self._require_tbs_cert_field('signature')
        self._require_tbs_cert_field('subject')
        self._require_tbs_cert_field('subject_public_key_info')
        self._require_tbs_cert_field('validity')
        self._require_tbs_cert_field('version')

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
                    "Extension value invalid! ext='{}' v='{}', req_v=''".format(field, e['extn_value'].native, value)
                )

        Certificate._require(False, 
            "Missing required extension field '{}'".format(field)
        )



class CscaCertificate(Certificate):
    def verify(self, nc_verify = False):
        self.verify(self, nc_verify)

    def verify(self, issuing_cert: x509.Certificate, nc_verify = False):
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        On failure CertificateVerificationError exception is risen.

        :param issuing_cert: The certificate that issued this certificate.
        :param nc_verify: Non-conformant verification, If True only signature will be verified.
        """

        super().verify(issuing_cert, nc_verify)

        # Verify certificate is conform to the ICAO specifications 
        if not nc_verify:
            super()._require_extension_field('subject_key_identifier')
            Certificate._require(self.subjectKey is not None, "Missing required field 'subjectKeyIdentifier' in SubjectKeyIdentifier extension")

            super()._require_extension_field('basic_constraints')
            Certificate._require('ca' in self.basic_constraints_values, "Missing 'ca' field in basic constraints")
            Certificate._require('max_path_length' in self.basic_constraints_values, "Missing 'ca' field in basic constraints")
            Certificate._require( self.max_path_length is None or 0 <= self.max_path_length <= 1, #Note: Portuguese cross-link CSCA has value 2
                            "Invalid CSCA path length constraint: {}".format(self.max_path_length)
            )

            super()._require_extension_field('key_identifier')

            super()._require_extension_field('key_usage')
            key_usage = self.key_usage_value.native
            Certificate._require( 'key_cert_sign' in key_usage, "Missing field 'keyCertSign' in KeyUsage extension")
            Certificate._require('crl_sign' in key_usage, "Missing field 'cRLSign' in KeyUsage extension")



class MasterListSignerCertificate(Certificate):
    def verify(self, issuing_cert: x509.Certificate, nc_verify = False):
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        On failure CertificateVerificationError exception is risen.

        :param issuing_cert: The certificate that issued this certificate.
        :param nc_verify: Non-conformant verification, If True only signature will be verified.
        """

        if self.ca: # Signer certificate is probably CSCA
                    # We do this check because not all master list issuers follow the specification rules and
                    # they use CSCA to sign master list instead of separate signer certificate issued by CSCA.
                    # See for example German master list no. 20190925)
            CscaCertificate.load(self.dump()).verify(issuing_cert, nc_verify)
        else:
            super().verify(issuing_cert, nc_verify)

            # Verify certificate is conform to the ICAO specifications 
            if not nc_verify:
                super()._require_extension_field('authority_key_identifier')
                Certificate._require(self.authorityKey is not None, "Missing required field 'keyIdentifier' in AuthorityKeyIdentifier extension")

                super()._require_extension_field('subject_key_identifier')
                Certificate._require(self.subjectKey is not None, "Missing required field 'subjectKeyIdentifier' in SubjectKeyIdentifier extension")

                super()._require_extension_field('key_usage')
                key_usage = self.key_usage_value.native
                Certificate._require(
                    'digital_signature' in key_usage,
                    "Missing field 'digitalSignature' in KeyUsage"
                )

                super()._require_extension_value('extended_key_usage', ['2.23.136.1.1.3']) #icao 9303-p12 p27



class DocumentSignerCertificate(Certificate):
    """ Document Signer Certificate (DSC) which should be used to verify SOD data file in eMRTD """

    def verify(self, issuing_cert: x509.Certificate, nc_verify = False) -> bool:
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        On failure CertificateVerificationError exception is risen.

        :param issuing_cert: The certificate that issued this certificate.
        :param nc_verify: Non-conformant verification, If True only signature will be verified.
        """

        super().verify(issuing_cert, nc_verify)

        if not nc_verify:
            super()._require_extension_field('authority_key_identifier')
            Certificate._require(self.authorityKey is not None, "Missing required field 'keyIdentifier' in AuthorityKeyIdentifier extension")

            super()._require_extension_field('subject_key_identifier')
            Certificate._require(self.subjectKey is not None, "Missing required field 'subjectKeyIdentifier' in SubjectKeyIdentifier extension")

            super()._require_extension_field('key_usage')
            key_usage = self.key_usage_value.native
            Certificate._require(
                'digital_signature' in key_usage,
                "Missing field 'digitalSignature' in KeyUsage"
            )