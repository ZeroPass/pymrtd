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
  - eMRTD trustchain public key certificates e.g.: [CSCA](https://github.com/ZeroPass/PassID-Server/blob/3a2d430abf3df95fdfdfa86159b12b48fd84aaf1/src/pymrtd/pki/x509.py#L113-L145), [DSC](https://github.com/ZeroPass/PassID-Server/blob/3a2d430abf3df95fdfdfa86159b12b48fd84aaf1/src/pymrtd/pki/x509.py#L185-L211) and [master list signer certificate](https://github.com/ZeroPass/PassID-Server/blob/3a2d430abf3df95fdfdfa86159b12b48fd84aaf1/src/pymrtd/pki/x509.py#L149-L181)  
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
*Note: Library has to be patched see [README](https://github.com/ZeroPass/PassID-Server/blob/master/src/pymrtd/pki/README.md) of pki module*
```
  pip3 install cryptography
```
