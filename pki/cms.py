from asn1crypto import algos, cms

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from pymrtd.pki import algo_utils, cert_utils, x509

from typing import List, NoReturn, Optional, Union


def cms_register_content_type(name, oid):
    cms.ContentType._map[oid] = name
    if cms.ContentType._reverse_map is None:
        cms.ContentType._reverse_map = { name : oid }
    else:
        cms.ContentType._reverse_map[name] = oid


def cms_register_encap_content_info_type(name, oid, type):
    cms_register_content_type(name, oid)
    cms.EncapsulatedContentInfo._oid_specs[name] = type


class MrtdSignedDataError(Exception):
    pass


class MrtdSignedData(cms.SignedData):
    _certificate_spec = x509.Certificate

    class CertificateSetOf(cms.CertificateSet):
        pass

    _fields = [ 
        *cms.SignedData._fields[0:3], 
        ('certificates', CertificateSetOf, {'implicit': 0, 'optional': True}),
        *cms.SignedData._fields[4:]
    ]

    CertList = Union[List[_certificate_spec], CertificateSetOf]

    def __init__(self, value=None, default=None, **kwargs):
        self.CertificateSetOf._child_spec  = self._certificate_spec
        super().__init__(value, default, **kwargs)

    @property
    def content(self):
         return self['encap_content_info']['content'].parsed

    @property
    def contentType(self):
         return self['encap_content_info']['content_type']

    @property
    def certificates(self) -> CertList :
        ''' Returns the list of certificates which signed signers info. '''
        return self['certificates']

    @property
    def digestAlgorithms(self) -> cms.DigestAlgorithms:
        return self['digest_algorithms']

    @property
    def signerInfos(self) -> cms.SignerInfos:
        ''' Returns SignerInfos object. '''
        return self['signer_infos']

    @property
    def version(self) -> cms.CMSVersion:
        return self['version']

    def getCertificateBySNI(self, sni: cms.IssuerAndSerialNumber) -> _certificate_spec:
        ''' Returns signer certificate identified by serial number and issuer '''
        return self.__class__._get_signer_cert_by_sni(self.certificates, sni)

    def getCertificateByKeyId(self, keyId: bytes)  -> _certificate_spec:
        ''' Returns signer certificate identified by subject key identifier '''
        return self.__class__._get_signer_cert_by_keyid(self.certificates, keyId)

    def getHasherBySidx(self, sidx) -> hashes.Hash:
        ''' Returns hashes.Hash object specified in SignerInfo returned from SignerInfos list by its index. '''

        si = self.signerInfos[sidx] 
        hash_algo = si['digest_algorithm']['algorithm'].native
        h = algo_utils.get_hash_algo_by_name(hash_algo)
        return hashes.Hash(h, backend=default_backend())

    def getSignatureBySidx(self, sidx) -> bytes:
        si = selfsignerInfos[sidx]
        return si['signature'].native

    def getSignedAttributesBySidx(self, sidx) -> cms.CMSAttributes:
        si = self.signerInfos[sidx]
        return si['signed_attrs']

    def getSigAlgoBySidx(self, sidx) -> algos.SignedDigestAlgorithm:
        ''' Returns SignedDigestAlgorithm specified in SignerInfo returned from SignerInfos list by its index. '''

        si = self.signerInfos[sidx] 
        hash_algo = si['digest_algorithm']['algorithm'].native
        sig_algo  = si['signature_algorithm']
        return algo_utils.update_sig_algo_if_no_hash_algo(sig_algo, hash_algo)

    def verify(self, certificateList: Optional[CertList] = []) -> NoReturn:
        ''' 
        Verifies every SignerInfo object and the digital signature over content.
        On failure MrtdSignedDataError exception is risen.
        :param certificateList: (Optional) List of signing certificates
        '''

        for sidx, si in enumerate(self.signerInfos):
            if si['version'].native == 'v1':
                sni = si['sid'].chosen
                c = self.getCertificateBySNI(sni)
                if c is None:
                    c = self.__class__._get_signer_cert_by_sni(certificateList, sni)
            elif si['version'].native == 'v3':
                keyid = si['sid'].native
                c = self.getCertificateByKeyId(keyid)
                if c is None:
                    c = self.__class__._get_signer_cert_by_keyid(certificateList, keyid)
            else:
                raise MrtdSignedDataError("Invalid SignerInfo version at sidx: {}".format(sidx))

            if c is None:
                raise MrtdSignedDataError("Signer Certificate not found")
            
            if 'signed_attrs' not in si:
                raise MrtdSignedDataError("Missing field 'signed_attrs' in signer infos")
            sa = si['signed_attrs']

            # Verify content
            md = None
            sig_time = None
            for a in sa:
                if a['type'].native == 'message_digest':
                    md = a['values'][0].native
                elif a['type'].native == 'signing_time':
                    sig_time = a['values'][0].native
                elif a['type'].native == 'content_type':
                    ct = a['values'][0]
                    if ct != self.contentType:
                        raise MrtdSignedDataError("signed content type doesn't match actual content type")

            if md is None:
                raise MrtdSignedDataError("Missing 'message_digest' signed attribute")

            if sig_time is not None and  not c.isValidOn(sig_time):
                raise MrtdSignedDataError("Invalid signing time")

            h = self.getHasherBySidx(sidx)
            h.update(self.content.dump())
            if h.finalize() != md:
                raise MrtdSignedDataError("Content digest doesn't match signed digest")

            # Make sure sa is asn1 SET type (DER tag 0x31)
            sa.tag    = 17
            sa.method = 1
            sa.class_ = 0

            signature = si['signature'].native
            sig_algo  = self.getSigAlgoBySidx(sidx)
            if not cert_utils.verify_sig(c, sa.dump(force=True), signature, sig_algo):
                raise MrtdSignedDataError("Signature verification failed")


    def _get_signer_cert_by_sni(cert_list: CertList, sni: cms.IssuerAndSerialNumber):
        for c in cert_list:
            if c.serial_number == sni['serial_number'].native and c.issuer == sni['issuer']:
                return c
        return None

    def _get_signer_cert_by_keyid(cert_list: CertList, keyid: bytes):
        for c in cert_list:
            if c.key_identifier == keyid:
                return c
        return None


class MrtdContentInfo(cms.ContentInfo):
    _signed_data_spec = MrtdSignedData

    def __init__(self, value=None, default=None, **kwargs):
        self._oid_specs['signed_data'] = self._signed_data_spec
        super().__init__(value, default, **kwargs)