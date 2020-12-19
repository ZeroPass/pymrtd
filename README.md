## Python library for ICAO Machine Readable Travel Documents standard - Biometric Passport
PyMRTD is python implementation of [ICAO 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303) standard.
PyMRTD implements only parts of standard needed for PassID server. That is, parsing (re-seralizing) some of MRTD logical data structures (LDS) files
and verifying eMRTD trustchain including verification of signature made by MRTD ([AA signature](https://github.com/ZeroPass/PassID-Server/blob/949d44b8bebe6d79cb529e8f7d9f922cb39e48a5/src/pymrtd/pki/keys.py#L231-L249)).
This library doesn't provide APIs and functionalities needed to send commands to and extract data from MRTD.

## Library structure
Library is devided into two modules:
* [ef](https://github.com/ZeroPass/PassID-Server/tree/master/src/pymrtd/ef) - Elementary file. This module defines LDS data structures
e.g.: [MRZ](https://github.com/ZeroPass/PassID-Server/blob/11a211266ac69616e2863ce4ea250d66329918b9/src/pymrtd/ef/mrz.py), [EF.SOD](https://github.com/ZeroPass/PassID-Server/blob/6abe36a9ffbfabed8c4f1d62722a00de0db47f3e/src/pymrtd/ef/sod.py#L135-L195), [EF.DG1](https://github.com/ZeroPass/PassID-Server/blob/6abe36a9ffbfabed8c4f1d62722a00de0db47f3e/src/pymrtd/ef/dg.py#L148-L158), [EF.DG14](https://github.com/ZeroPass/PassID-Server/blob/6abe36a9ffbfabed8c4f1d62722a00de0db47f3e/src/pymrtd/ef/dg.py#L161-L185) and [EF.DG15](https://github.com/ZeroPass/PassID-Server/blob/6abe36a9ffbfabed8c4f1d62722a00de0db47f3e/src/pymrtd/ef/dg.py#L189-L203).
* [pki](https://github.com/ZeroPass/PassID-Server/tree/master/src/pymrtd/pki) - eMRTD Public Key Infrastructure:  
  - eMRTD trustchain public key certificates e.g.: [CSCA](https://github.com/ZeroPass/PassID-Server/blob/3a2d430abf3df95fdfdfa86159b12b48fd84aaf1/src/pymrtd/pki/x509.py#L121-L153), [DSC](https://github.com/ZeroPass/PassID-Server/blob/3a2d430abf3df95fdfdfa86159b12b48fd84aaf1/src/pymrtd/pki/x509.py#L193-L219) and [master list signer certificate](https://github.com/ZeroPass/PassID-Server/blob/3a2d430abf3df95fdfdfa86159b12b48fd84aaf1/src/pymrtd/pki/x509.py#L157-L189)  
  - [Certificate revocation list (CRL)](https://github.com/ZeroPass/PassID-Server/blob/949d44b8bebe6d79cb529e8f7d9f922cb39e48a5/src/pymrtd/pki/crl.py)
  - [CSCA master list](https://github.com/ZeroPass/PassID-Server/blob/949d44b8bebe6d79cb529e8f7d9f922cb39e48a5/src/pymrtd/pki/ml.py#L40-L87)
  - Functions and procedures to verify digital signatures including RSA [ISO9796-2 DSS1](https://github.com/ZeroPass/PassID-Server/blob/949d44b8bebe6d79cb529e8f7d9f922cb39e48a5/src/pymrtd/pki/iso9796e2.py)
## Dependencies
* [Python 3.7 or higher](https://www.python.org/downloads/).<br>
  Check this [website](https://wiki.python.org/moin/BeginnersGuide/Download) for installation guidelines.

* [asn1crypto](https://github.com/wbond/asn1crypto)
```
 pip3 install asn1crypto
```

* [cryptography](https://github.com/pyca/cryptography)
```
  pip3 install cryptography
```

## Usage
### Parsing and serializing data stuctures
All data structures that can be parsed from raw byte array (SOD, DG1, CscaCertificate etc...) have defined 
static member function `load` and member function `dump` to serialize data back to byte array (following the interface of library *asn1crypto*).

Example of loading CscaCertificate from file:
```python
f = open('csca.cer', 'rb')
csca = CscaCertificate.load(f.read())

print(csca.issuerCountry)
print(csca.subjectKey.hex())
print(csca.fingerprint)
print(csca.dump().hex())
```

### Verifying and validating
All certificate classes (Certificate, CscaCertificate, DocumentSignerCertificate, MasterListSignerCertificate) and also classes implementing [MRTD CMS](https://github.com/ZeroPass/PassID-Server/blob/45d92ef090506db3d202178b5742854ebebf16fd/src/pymrtd/pki/cms.py#L180) data structure ([RFC 5652](https://tools.ietf.org/html/rfc5652)) have member function `verify` defined which verifies digital signature made over an object.
Classes implementing class `Certificate` has also defined member function `isValidOn(datetime)` which returns `True` if certificate is valid on particular date and time.

Example of validating MRTD trustchain:
```python
# 1. Parse SOD and get signing certificates (DSC, CSCA)
sod = SOD.load(...)
if len(sod.dsCertificates) == 0: # SOD is not required to store it's signer DSC certificate. 
  raise Exception("Can't verify SOD, no DSC found")
  
dsc  = sod.dsCertificates[0] # SOD can store more than 1 DSC certificate by definition
csca = fetchCSCAofDSC(sod.dsCertificates[0])
if csca is None:
  raise Exception("Can't verify DSC, no CSCA found")
  
# 2. Validate trust chain by verifying digital signatures and expiration time of certificates
if not csca.isValidOn(utils.time_now()):
  raise Exception("CSCA has expired")
  
if not dsc.isValidOn(utils.time_now()):
  raise Exception("DSC has expired")
  
try:
  # Note: certificate conformance check (nc_verification) is not done by default
  #       because not all countries follow the standard strictly
  dsc.verify(issuing_cert=csca, nc_verification=True/False)   
  sod.verify() # optionally, a list of DSC certificates can be provided
except:
  raise Exception("MRTD turstchain verification failed")
```

Example of verifying MRTD digital signature:
```python
sod  = SOD.load(...)
dg15 = DG15.load(...)

# First verify DG15 was issued by country
# Note: SOD object should be validated into trustchain at this point
if not sod.ldsSecurityObject.contains(dg15):
  raise Exception("Can't verify signature, invalid EF.DG15 file")

# If ECC signature, get ECC signature algorithm from EF.DG14 file
sigAlgo = None
if dg15.aaPublicKey.isEcKey():
  dg14 = SOD.load(...)
  if not sod.ldsSecurityObject.contains(dg14): # Verify EF.DG14 was issued by country
    raise Exception("Can't verify signature, invalid EF.DG14 file")
  elif dg14.aaSignatureAlgo is None: # sanity check
    raise Exception("Missing ActiveAuthenticationInfo in DG14 file")
  sigAlgo = dg14.aaSignatureAlgo

# Verify signature made by MRTD
try:
  dg15.aaPublicKey.verifySignature(msg, sig, sigAlgo):
catch:
  raise Exception("Signature verification failed")
```

## Other documentation
* [ICAO 9303 Specifications Common to all MRTDs](https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf)
* [ICAO 9303 Specifications for Machine Readable Passports (MRPs) and other TD3 Size MRTDs](https://www.icao.int/publications/Documents/9303_p4_cons_en.pdf)
* [ICAO 9303 eMRTD logical data structure](https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf)
* [ICAO 9303 Security mechanisms for MRTDs](https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf)
