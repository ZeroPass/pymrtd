from asn1crypto import x509
from datetime import datetime
from typing import Optional

from .oids import id_icao_cscaMasterListSigningKey #pylint: disable=relative-beyond-top-level
from .cert_utils import verify_cert_sig #pylint: disable=relative-beyond-top-level

import asn1crypto.core as asn1

class CertificateVerificationError(Exception):
    pass

class Certificate(x509.Certificate):
    @property
    def fingerprint(self) -> str:
        """Returns hex str of the first 8 bytes of sha256 hash of self"""
        return self.sha256[0:8].hex().upper().rjust(16, '0')

    @property
    def issuerCountry(self) -> Optional[str]:
        """
        Function returns country of certificate issuer.
        :return: Issuer country code. Note, can return None in non-conformant certificates.
        """
        country = None
        if self.issuer is not None and 'country_name' in self.issuer.native:
            country = self.issuer.native['country_name']
        return country

    @property
    def subjectKey(self) -> Optional[bytes]:
        """Function returns subject key of certificate"""
        return self.key_identifier

    @property
    def authorityKey(self) -> Optional[bytes]:
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
        :raises: CertificateVerificationError if conformance check fails.
        """
        self._verify_cert_fields()
        self._verify_tbs_cert_fields()

    def nameChanged(self) -> bool:
        """
        Checks if certificate contains MRTD specific extension
        with OID=2.23.136.1.1.6.1 which indicates CSCA certificate DN name change.
        See ICAO 9303 part 12, section 7.1.1.5.
        https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf
        :return: True if certificate DN name has changed, otherwise False.
        """
        for e in self.native['tbs_certificate']['extensions']:
            if e['extn_id'] == '2.23.136.1.1.6.1':
                return True
        return False

    def verify(self, issuerCert: x509.Certificate, checkConformance = False) -> None:
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        :param issuerCert: The certificate that issued this certificate
        :param checkConformance: X.509 certificate conformance verification, if False only signature will be verified.
                                 Conformance verification can also be done through checkConformance method.
        :raises CertificateVerificationError: On failed signature verification or failed Conformance check.
        :raises *Exception: If there was a problem in the process before signature is fully verified.
             See cert_utils.verify_sig
        """

        # Verify certificate is conform to the basic X.509 standard
        if checkConformance:
            self.checkConformance()

        if not verify_cert_sig(self, issuerCert):
            raise CertificateVerificationError("Signature verification failed")

    @staticmethod
    def _require(cond, message: str):
        if not cond:
            raise CertificateVerificationError(message)

    def _require_cert_field(self, field: str):
        Certificate._require(field in self,
            f"Missing required certificate field '{field}'"
        )

    def _verify_cert_fields(self):
        self._require_cert_field('tbs_certificate')
        self._require_cert_field('signature_algorithm')
        self._require_cert_field('signature_value')

    def _require_tbs_cert_field(self, field: str):
        Certificate._require(field in self['tbs_certificate'],
            f"Missing required tbs certificate field '{field}'"
        )

    def _verify_tbs_cert_fields(self):
        # Note, we don't check if the certificate has common_name (CN) in the subject and issuer field as required by ICAO 9303 part 12 section 7.1.1.1.1.
        # The reason for not checking is that some valid CSCA certificates (and possible DSC) are missing this field. e.g. US CSCA certificates
        self._require_tbs_cert_field('extensions')
        self._require_tbs_cert_field('issuer')
        self._require_tbs_cert_field('serial_number')
        self._require_tbs_cert_field('signature')
        self._require_tbs_cert_field('subject')
        self._require_tbs_cert_field('subject_public_key_info')
        self._require_tbs_cert_field('validity')
        self._require_tbs_cert_field('version')

        Certificate._require('country_name' in self.issuer.native, # ICAO 9303 part 12 section 7.1.1.1.1
            "Issuer field is missing field 'country_name'"
        )
        cn = self.issuer.native['country_name']
        Certificate._require( len(cn) == 2, # ICAO 9303 part 12 section 7.1.1.1.1
            f'Invalid country name in issuer field: {cn}'
        )

        Certificate._require('country_name' in self.subject.native, # ICAO 9303 part 12 section 7.1.1.1.1
            "Subject field is missing field 'country_name'"
        )
        cn = self.subject.native['country_name']
        Certificate._require( len(cn) == 2, # ICAO 9303 part 12 section 7.1.1.1.1
            f'Invalid country name in subject field: {cn}'
        )

    def _require_extension_field(self, field: str):
        exts = self['tbs_certificate']['extensions']
        for e in exts:
            if field in e['extn_id'].native:
                return
        Certificate._require(False,
            f"Missing required extension field '{field}'"
         )

    def _require_extension_value(self, field: str, value):
        exts = self['tbs_certificate']['extensions']
        for e in exts:
            if field in e['extn_id'].native:
                if e['extn_value'].native == value:
                    return
                Certificate._require(False,
                    f"Extension value invalid! ext='{field}' v='{e['extn_value'].native}', req_v='{value}'"
                )

        Certificate._require(False,
            f"Missing required extension field '{field}'"
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
            - requirement for the value of path length constraint to be 0 or 1 (if present).
              If max path length is not present it should be assumed then that
              the max path length is either 0 for CSCA or 1 for LCSCA.

              Note: ICAO 9303 specs require max path length to be 0 or 1 for LCSCA.
                    This implementation just check that the path length constraint
                    to be either of the 2 values but doesn't check for the cert type i.e. is it CSCA or LCSCA.
                    The reason for this is that not all CSCA/LCSCA follow this strictly.
                    Note, there are also certificate with greater value for the path length constraint.
                    Such certificate will be rejected by this function.

        :raises: CertificateVerificationError if conformance check fails.
        :raises *Exception: If there was a problem in the process before signature is fully verified.
             See cert_utils.verify_sig
        """
        # Check first conformance to the X.509 standard
        super().checkConformance()

        # Now verify CSCA conforms to the ICAO specifications
        Certificate._require(self.issuerCountry.lower() == self.subject.native['country_name'].lower(), # ICAO 9303 part 12, 7.1.1
            "The subject and issuer country doesn't match"
        )

        super()._require_extension_field('basic_constraints')
        Certificate._require(self.ca == True, "CSCA certificate must be root CA")

        # ICAO 9303 part 12 7.1.1 specs require PathLenConstraint extension to be present but there can be some CSCA certificates
        # which don't contain this extension. Because of this we lessen this restriction here and assume if this extension is not present
        # the value of PathLenConstraint is 0 for CSCA or 1 for LCSCA.
        if self.max_path_length is not None:
            Certificate._require( 0 <= self.max_path_length <= 1, #Note: Portuguese cross-link CSCA has value 2
                f'Invalid CSCA path length constraint: {self.max_path_length}'
            )

        super()._require_extension_field('key_usage')
        key_usage = self.key_usage_value.native
        Certificate._require( 'key_cert_sign' in key_usage, "Missing field 'keyCertSign' in KeyUsage extension")
        Certificate._require('crl_sign' in key_usage, "Missing field 'cRLSign' in KeyUsage extension")

        super()._require_extension_field('key_identifier')
        Certificate._require(self.subjectKey is not None,
            "Missing required field 'subjectKeyIdentifier' in SubjectKeyIdentifier extension"
        )

    def verify(self, issuerCert: Optional[x509.Certificate] = None, checkConformance: bool = False):
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        :param issuerCert: (Optional) The certificate that issued this certificate.
                            If None, this certificate will be used as issuing certificate to verify the certificate signature.
        :param checkConformance: X.509 and ICAO 9303 CSCA conformance verification, if False only signature will be verified.
                                 Conformance verification can also be done through checkConformance method
        :raises CertificateVerificationError: On failed signature verification or failed Conformance check.
        :raises *Exception: If there was a problem in the process before signature is fully verified.
             See cert_utils.verify_sig
        """
        if issuerCert is None:
            issuerCert = self
        super().verify(issuerCert, checkConformance)


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
        :raises: CertificateVerificationError if conformance check fails.
        """
        # Check first conformance to the X.509 standard
        super().checkConformance()

        # Now verify master list signer certificate conforms to the ICAO specifications
        Certificate._require(self.issuerCountry.lower() == self.subject.native['country_name'].lower(),  # ICAO 9303 part 12, 7.1.1
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

    def verify(self, issuerCert: x509.Certificate, checkConformance: bool = False):
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        :param issuerCert: The certificate that issued this certificate.
        :param checkConformance: X.509 and ICAO 9303 master list signer certificate conformance verification,
                                 if False only signature will be verified.
                                 Conformance verification can also be done through checkConformance method
        :raises CertificateVerificationError: On failed signature verification or failed Conformance check.
        :raises *Exception: If there was a problem in the process before signature is fully verified.
             See cert_utils.verify_sig
        """
        if self.ca: # Signer certificate is probably CSCA
                    # We do this check because not all master list issuers follow the specification rules and
                    # they use CSCA to sign master list instead of separate signer certificate issued by CSCA.
                    # See for example German master list no. 20190925)
            CscaCertificate.load(self.dump()).verify(issuerCert, checkConformance)
        else:
            super()._require_extension_value('extended_key_usage', [id_icao_cscaMasterListSigningKey]) #icao 9303-p12 p20, p27
            super().verify(issuerCert, checkConformance)


class DocumentTypeListSyntax(asn1.Sequence):
    """
    Defines list of document types of which documents the DSC certificate can sign.
    The document type as contained in MRZ, e.g. "P" or "ID" where a
    single letter denotes all document types starting with that letter
    where 2 letters denote document mayor type and document sub type.
    Some types: P = passport, I - id card
    See also pymrtd.ef.mrz.DocumentType
    """
    # Note: Document ICAO-9303-p12 7.1.6 defines the doc. types to be put into single SET OF docTypeList,
    #       but examining some DSC certificates showed that some CA implemented it wrongly and put
    #       each doc. type in their own SET OF list object.
    #       Example of such DSC certificate would be a Moldovan DSC ser. no.:  02B27F8C79935F02
    #       Parsing of invalid encoded docTypeList will result in partially parsed or unparsed list.
    # TODO: Try parse invalid encoded docTypeList
    _fields = [
        ('version', asn1.Integer),
        ('docTypeList', asn1.SetOf, {'spec': asn1.PrintableString})
    ]

    @property
    def version(self) -> int:
        return super().__getitem__('version').native

    def contains(self, docType: str) -> bool:
        """
        Function check if list contains specific document type.
        :param docType: Document type to verify. Single letter denotes mayjor type. e.g. P, PB, I, ID
        :return: If docType is single letter i.e. major type than True is returned
        on first occurrence of document type in the list that begins with that letter.
        Otherwise True is returned only if docType matches any of the full types in the list.
        """
        majorType = len(docType) == 1
        for t in self:
            if majorType:
                if t.native[0] == docType:
                    return True
            elif t.native == docType:
                return True
        return False

    def __len__(self):
        return len(self._get_list())

    def __getitem__(self, key):
        return self._get_list().__getitem__(key)

    def __iter__(self):
        return self._get_list().__iter__()

    def _get_list(self) -> asn1.SetOf:
        return super().__getitem__('docTypeList')


class DocumentSignerCertificate(Certificate):
    """ Document Signer Certificate (DSC) which should be used to verify SOD data file in eMRTD """

    _fields = Certificate._fields
    _fields[0][1]._fields[9][1]._child_spec._oid_specs['icao_mrtd_document_type_list'] = DocumentTypeListSyntax #pylint: disable=protected-access
    _fields[0][1]._fields[9][1]._child_spec._fields[0][1]._map['2.23.136.1.1.6.2'] = 'icao_mrtd_document_type_list' # DS document type #pylint: disable=protected-access

    #  The DS document type (icao-mrtd-security-extensions-document-type-list) is prioriterized as DSC
    #  should have DS document type extension and not document type list (icao-mrtd-security-document-type-list).
    #  We allow document type list anyways because some DSC has this extension insted of DS document type.
    #  For example French DSC certificate ser. no.: 1121a7f221c464815d0ea81f6bf56a4d8edc
    _fields[0][1]._fields[9][1]._child_spec._fields[0][1]._map['2.23.136.1.1.4'] = 'icao_mrtd_document_type_list' #pylint: disable=protected-access
    _icao_mrtd_document_type_list_value = None

    @property
    def documentTypes(self) -> Optional[DocumentTypeListSyntax]:
        """
        Returns the list of document types (as type appear in the MRZ) this DSC can sign.
        Note, the DSC certificate must contain extension icao-mrtd-security-extensions-document-type-list (OID=2.23.136.1.1.6.2) or
        icao-mrtd-security-document-type-list (OID=2.23.136.1.1.4), otherwise None is returned.
        See doc: ICAO 9303 part 12, section 7.1.1.6
                 https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf

        :return Optional[DocumentTypeListSyntax]: List of document types DSC certificate can sign or None.
        """
        if not self._processed_extensions:
            self._set_extensions()
        return self._icao_mrtd_document_type_list_value


    def checkConformance(self) -> None:
        """
        Verifies that this DSC certificate conform to the basic X.509 and ICAO 9303 standard.
        See ICAO 9303 part 12, 7.1.1 Certificate Profile and Appendix B and C to the Part 12.
        https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf

        This method first verifies that DSC conforms to the X.509 standard, see Certificate.checkConformance().
        Then verifies conformance to the ICAO 9303 standard:
            - requirement for the subject and issuer field to have the same country value.
            - requirement for the key usage value to contain digitalSignature.
        :raises: CertificateVerificationError if conformance check fails.
        """
        # Check first DSC conformance to the X.509 standard
        super().checkConformance()

        # Now verify DSC conforms to the ICAO specifications
        Certificate._require(self.ca is None or self.ca == False, "DSC certificate must not be root CA") #pylint: disable=singleton-comparison
        Certificate._require(self.self_signed == 'no', "DSC certificate must not be self-issued")
        Certificate._require(self.issuerCountry.lower() == self.subject.native['country_name'].lower(),  # ICAO 9303 part 12, 7.1.1
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

    def verify(self, issuerCert: x509.Certificate, checkConformance: bool = False):
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        :param issuerCert: The certificate that issued this certificate.
        :param checkConformance: X.509 and ICAO 9303 DSC conformance verification, if False only signature will be verified.
                                 Conformance verification can also be done through checkConformance method
        :raises CertificateVerificationError: On failed signature verification or failed Conformance check.
        :raises *Exception: If there was a problem in the process before signature is fully verified.
             See cert_utils.verify_sig
        """
        super().verify(issuerCert, checkConformance)
