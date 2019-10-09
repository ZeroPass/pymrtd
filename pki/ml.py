from asn1crypto import cms
from asn1crypto.algos import SignedDigestAlgorithm
import asn1crypto.core as asn1

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from pymrtd.pki import algo_utils, cert_utils
from .x509 import CscaCertificate, MasterListSignerCertificate


class CertList(asn1.SetOf):
    _child_spec = CscaCertificate

class CscaList(asn1.Sequence):
    _fields = [
        ('version', asn1.Integer),
        ('certList', CertList)
    ]

    def version(self) -> int:
        return super().__getitem__('version').native

    def __len__(self):
        return len(self._get_list())

    def __getitem__(self, key):
        return self._get_list().__getitem__(key)

    def __iter__(self):
        return self._get_list().__iter__()

    def _get_list(self) -> CertList:
        return super().__getitem__('certList')


class CscaMasterListError(Exception):
    pass


class CscaMasterList():
    def __init__(self, cms_bytes):
        self._cms = cms.ContentInfo.load(cms_bytes)

        ctype = self._cms['content_type'].native
        if ctype != 'signed_data': # ICAO 9303-12-p25
            raise CscaMasterListError("Invalid master list content type: {}, should be 'signed_data'".format(ctype))

        cver = self._cms['content']['version'].native
        if cver != 'v3': # ICAO 9303-12-p25
            raise CscaMasterListError("Invalid SignedData version: {}, should be 'v3'".format(cver))

        econt_type = self._cms['content']['encap_content_info']['content_type'].native
        if econt_type != '2.23.136.1.1.2': # ICAO 9303-12-p26
            raise CscaMasterListError("Invalid encapContentInfo type: {}, should be '2.23.136.1.1.2'".format(econt_type))

        econt        = self._cms['content']['encap_content_info']['content'].native
        self._cscal  = CscaList.load(econt)
        if self._cscal.version() != 0: # ICAO 9303-12-p27
            raise CscaMasterListError("Unsupported encapContentInfo version: {}, should be 0".format(self._cscal.version()))
        
        self._mls_certs = []
        certs = self._cms['content']['certificates']
        if len(certs) < 1:
            raise CscaMasterListError("No master list signing certificate found") 

        for cc in certs:
            cc.chosen.__class__ = MasterListSignerCertificate
            self._mls_certs.append(cc.chosen)

    def getSignerCertificates(self):
        ''' Returns the list of Master List Signer certificates. '''
        return self._mls_certs

    def getSignerCertificateBySN(self, serialNum):
        for c in self._mls_certs:
            if c.serial_number == serialNum:
                return c
        raise CscaMasterListError("Signer certificate not found")

    def getSignerCertificateByKeyId(self, keyId: bytes):
        for c in self._mls_certs:
            if c.key_identifier == keyId:
                return c
        raise CscaMasterListError("Signer certificate not found")

    def getCscaList(self):
        ''' Returns list of CSCAs '''
        return self._cscal

    def getHasherBySidx(self, sidx):
        ''' Returns hashes.Hash object specified in SignerInfo returned from SignerInfos list by its index. '''

        si = self._cms['content']['signer_infos'][sidx] 
        hash_algo = si['digest_algorithm']['algorithm'].native
        h = algo_utils.get_hash_algo_by_name(hash_algo)
        return hashes.Hash(h, backend=default_backend())

    def getSignatureBySidx(self, sidx):
        si = self._cms['content']['signer_infos'][sidx]
        return si['signature'].native

    def getSignedAttributesBySidx(self, sidx):
        si = self._cms['content']['signer_infos'][sidx]
        return si['signed_attrs']

    def getSigAlgoBySidx(self, sidx):
        ''' Returns SignedDigestAlgorithm specified in SignerInfo returned from SignerInfos list by its index. '''

        si = self._cms['content']['signer_infos'][sidx] 
        hash_algo = si['digest_algorithm']['algorithm'].native
        sig_algo  = si['signature_algorithm']
        return algo_utils.update_sig_algo_if_no_hash_algo(sig_algo, hash_algo)

    def verify(self):
        ''' 
        Verifies every SignerInfo object and the digital signature over content.
        On failure CscaMasterListError exception is risen.
        '''

        for sidx, si in enumerate(self._cms['content']['signer_infos']):
            if si['version'].native == 'v1':
                c = self.getSignerCertificateBySN(si['sid'].native['serial_number'])
            elif si['version'].native == 'v3':
                c = self.getSignerCertificateByKeyId(si['sid'].native)
            else:
                raise CscaMasterListError("Invalid SignerInfo version at sidx: {}".format(sidx))
            
            if 'signed_attrs' not in si:
                raise CscaMasterListError("Missing field 'signed_attrs' in signer infos")
            sa = si['signed_attrs']

            # Verify content
            md = None
            sig_time = None
            for a in sa:
                if a['type'].native == 'message_digest':
                    md = a['values'][0].native
                elif a['type'].native == 'signing_time':
                    sig_time = a['values'][0].native

            if md is None:
                raise CscaMasterListError("Missing 'message_digest' signed attribute")

            if sig_time is None:
                raise CscaMasterListError("Missing 'signing_time' signed attribute")

            if not c.isValidOn(sig_time):
                raise CscaMasterListError("Invalid signing time")

            h = self.getHasherBySidx(sidx)
            h.update(self._cscal.dump())
            if h.finalize() != md:
                raise CscaMasterListError("Content's digest doesn't match signed digest")

            # Make sure sa is asn1 SET type (DER tag 0x31)
            sa.tag    = 17
            sa.method = 1
            sa.class_ = 0

            signature = si['signature'].native
            sig_algo  = self.getSigAlgoBySidx(sidx)
            if not cert_utils.verify_sig(c, sa.dump(force=True), signature, sig_algo):
                raise CscaMasterListError("Signature verification failed")