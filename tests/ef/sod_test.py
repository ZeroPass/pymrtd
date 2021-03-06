
import os
import py
import pytest

from asn1crypto.cms import IssuerAndSerialNumber
from pymrtd import ef
from pymrtd.ef.dg import DataGroupNumber
from pymrtd.pki.x509 import DocumentSignerCertificate

_dir = os.path.dirname(os.path.realpath(__file__))
CERTS_DIR = py.path.local(_dir) /'..'/'pki'/'certs'

@pytest.mark.depends(on=[
    'tests/ef/ef_base_test.py::test_ef_base',
    'tests/ef/dg_base_test.py::test_dg_base',
    'tests/ef/dg1_test.py::test_dg1',
    #'tests/ef/dg1_test.py::test_dg14',
    #'tests/ef/dg1_test.py::test_dg15'
])
@pytest.mark.datafiles(
    CERTS_DIR / 'dsc_de_0142fd5cf927.cer',
    CERTS_DIR / 'dsc_de_0130846f2b3e.cer'
)
def test_sod(datafiles):
    assert issubclass(ef.SOD, ef.ElementaryFile)

    # Test vector taken from German BSI TR-03105-5 ReferenceDataSet
    # https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03105/BSI_TR-03105-5_ReferenceDataSet_zip.html
    # EF_SOD.bin
    tv_sod = bytes.fromhex('7782078A3082078606092A864886F70D010702A082077730820773020103310F300D060960864801650304020105003081E90606678108010101A081DE0481DB3081D8020100300D060960864801650304020105003081C3302502010104204170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B630250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA08204653082046130820295A00302010202060142FD5CF927304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A50205042204353301E170D3133313231363231343331385A170D3134313231313231343331385A3054310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731183016060355040B0C0F446F63756D656E74205369676E65723112301006035504030C09484A5020504220445330820122300D06092A864886F70D01010105000382010F003082010A02820101009E7CBB065377041232915A044DD3ADC2199AD4C14BC8E58C24A899DBD62A984EEAE2A0006C1D53439246A67A9964D759BC7B9426CE6C4C078363306CF66645F12F39D950FE2C04100E6FF53C310B52F74CD1ED89931496F376D384AB604A570129445F015FCC3595E161B7C591CB5206BC16477D8CDEC09480DBF6262696F62970DA0978807DBA330EE777BF54D471AE1EB257090F1379E198A2D1503344847347BE46764FA00C4E93BACD32143B2E04C6C369CECE7943FD414521849533F9CDB985E42767F1DD792E7EFED3651E3C75DF868FA2101DF45CD5D3D955B23A88DD30A752F4FB9F4E84B518E0CA0F8F2BACE65D61F98115A0EA88DD3A3416017CA30203010001A3523050301F0603551D230418301680141E4D57560C12902366A8FDE11408A37F70EB7D65301D0603551D0E04160414831C30BE878FDF57273010E5B38950E576F7B08A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012003820181002984DC43028839BB24786A4C9C9C37E76368FF6264707970E5B00F7934840904ED90E34B018D5D634D7536E49AFE7B0E872F5D093E6D11BF31C910686A9106F9F773F59C57AEFF983DE6335B5CB403E0FF7D3055F09948878F8BE1BC184F2A03C82C14097FC19DEDDCCF61A2EAE6F8BF1A64BE4C0253CE0BC35AD41E10D6FF08C1EE872349E8D02A722F48144CAB665D0FADF9DB3B36BFB2B15AE4A3B13DC4CF64133B599CDB3AF8A365AC6228096899FEA8D56A24F90DA72B3E95B97FD82C4B8EF9CBB499C3D9F09053A5FDDD51E94A13A004530D74F7DD1B0C88163F9BFA098923DC81D247D75E33CAC3C7E27AEAC627B99AB18E6B03D38260E2DCCFA1D638D17614773BC13EBA0D53E2E3E9A202E0742C25DF471072CDA2A88BA2B25648970BC31132DE84F702ABBC98740B4FEE7C66CD149755A763B801DCF9DC1B52191A3ACC514244C51D297F35E5AEA328B8641B33D54DC7C50D2466F9DDDCE98A75F276D48D614B6C4FA675C2017824BED7CC27B46FCBE5B82CE4B433E34AAED2EBEE3182020630820202020101305D3053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A5020504220435302060142FD5CF927300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
    sod = ef.SOD.load(tv_sod)
    assert sod.dump()                                                          == tv_sod
    assert len(sod.content.children)                                           == 2
    assert sod.content.native['content_type']                                  == 'signed_data'
    assert sod.content.native['content']['version']                            == 'v3'
    assert len(sod.content.native['content']['digest_algorithms'])             == 1
    assert sod.content.native['content']['digest_algorithms'][0]['algorithm']  == 'sha256'
    assert sod.content.native['content']['encap_content_info']['content_type'] == 'ldsSecurityObject'
    assert sod.signedData.contentType.native                                   == 'ldsSecurityObject'

    # LDS SecurityObject test
    assert sod.ldsSecurityObject.version.native                            == 'v0'
    assert sod.ldsSecurityObject.ldsVersion.native                         is None
    assert sod.ldsSecurityObject.dgHashAlgo['algorithm'].native            == 'sha256'
    assert sod.ldsSecurityObject.dgHashAlgo['parameters'].native           is None

    assert len(sod.ldsSecurityObject.dgHashes)                             == 5
    assert sod.ldsSecurityObject.dgHashes.native[0]['dataGroupNumber']     == 'EF.DG1'
    assert sod.ldsSecurityObject.dgHashes.children[0].number               == DataGroupNumber(1)
    assert sod.ldsSecurityObject.dgHashes.native[0]['dataGroupHashValue']  == bytes.fromhex('4170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B6')
    assert sod.ldsSecurityObject.dgHashes.children[0].hash                 == bytes.fromhex('4170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B6')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(1))     == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(1)).number  == DataGroupNumber(1)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(1)).hash    == bytes.fromhex('4170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B6')
    assert sod.ldsSecurityObject.find(DataGroupNumber(1)).number           == DataGroupNumber(1)
    assert sod.ldsSecurityObject.find(DataGroupNumber(1)).hash             == bytes.fromhex('4170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B6')

    assert sod.ldsSecurityObject.dgHashes.native[1]['dataGroupNumber']     == 'EF.DG2'
    assert sod.ldsSecurityObject.dgHashes.children[1].number               == DataGroupNumber(2)
    assert sod.ldsSecurityObject.dgHashes.native[1]['dataGroupHashValue']  == bytes.fromhex('A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E54745')
    assert sod.ldsSecurityObject.dgHashes.children[1].hash                 == bytes.fromhex('A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E54745')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(2))     == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(2)).number  == DataGroupNumber(2)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(2)).hash    == bytes.fromhex('A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E54745')
    assert sod.ldsSecurityObject.find(DataGroupNumber(2)).number           == DataGroupNumber(2)
    assert sod.ldsSecurityObject.find(DataGroupNumber(2)).hash             == bytes.fromhex('A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E54745')

    assert sod.ldsSecurityObject.dgHashes.native[2]['dataGroupNumber']     == 'EF.DG3'
    assert sod.ldsSecurityObject.dgHashes.children[2].number               == DataGroupNumber(3)
    assert sod.ldsSecurityObject.dgHashes.native[2]['dataGroupHashValue']  == bytes.fromhex('403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00')
    assert sod.ldsSecurityObject.dgHashes.children[2].hash                 == bytes.fromhex('403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(3))     == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(3)).number  == DataGroupNumber(3)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(3)).hash    == bytes.fromhex('403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00')
    assert sod.ldsSecurityObject.find(DataGroupNumber(3)).number           == DataGroupNumber(3)
    assert sod.ldsSecurityObject.find(DataGroupNumber(3)).hash             == bytes.fromhex('403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00')

    assert sod.ldsSecurityObject.dgHashes.native[3]['dataGroupNumber']     == 'EF.DG14'
    assert sod.ldsSecurityObject.dgHashes.children[3].number               == DataGroupNumber(14)
    assert sod.ldsSecurityObject.dgHashes.native[3]['dataGroupHashValue']  == bytes.fromhex('CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE')
    assert sod.ldsSecurityObject.dgHashes.children[3].hash                 == bytes.fromhex('CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(14))    == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(14)).number == DataGroupNumber(14)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(14)).hash   == bytes.fromhex('CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE')
    assert sod.ldsSecurityObject.find(DataGroupNumber(14)).number          == DataGroupNumber(14)
    assert sod.ldsSecurityObject.find(DataGroupNumber(14)).hash            == bytes.fromhex('CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE')

    assert sod.ldsSecurityObject.dgHashes.native[4]['dataGroupNumber']     == 'EF.DG4'
    assert sod.ldsSecurityObject.dgHashes.children[4].number               == DataGroupNumber(4)
    assert sod.ldsSecurityObject.dgHashes.native[4]['dataGroupHashValue']  == bytes.fromhex('4C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17B')
    assert sod.ldsSecurityObject.dgHashes.children[4].hash                 == bytes.fromhex('4C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17B')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(4))     == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(4)).number  == DataGroupNumber(4)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(4)).hash    == bytes.fromhex('4C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17B')
    assert sod.ldsSecurityObject.find(DataGroupNumber(4)).number           == DataGroupNumber(4)
    assert sod.ldsSecurityObject.find(DataGroupNumber(4)).hash             == bytes.fromhex('4C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17B')

    hasher = sod.ldsSecurityObject.getDgHasher()
    assert hasher.algorithm.name == 'sha256'
    tv_dg1 = ef.DG1.load(bytes.fromhex('615B5F1F58503C443C3C4D55535445524D414E4E3C3C4552494B413C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C433131543030324A4D34443C3C3936303831323246323331303331343C3C3C3C3C3C3C3C3C3C3C3C3C3C3C34'))
    hasher.update(tv_dg1.dump())
    assert sod.ldsSecurityObject.find(DataGroupNumber(1)).hash == hasher.finalize()
    assert sod.ldsSecurityObject.contains(tv_dg1)              == True

    hasher = sod.ldsSecurityObject.getDgHasher()
    assert hasher.algorithm.name == 'sha256'
    tv_dg14 = ef.DG14.load(bytes.fromhex('6E82014A3182014630820122060904007F000702020102308201133081D406072A8648CE3D02013081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101033A0004A847F020F71DF33D386BE7C9223A354D6AC7727018B26E281C6FFB96A83B142AAF303C23F2BCF2CDE4706C14E45914A9BE42C15BCB67A01F300F060A04007F00070202030201020101300D060804007F0007020202020101'))
    hasher.update(tv_dg14.dump())
    assert sod.ldsSecurityObject.find(DataGroupNumber(14)).hash == hasher.finalize()
    assert sod.ldsSecurityObject.contains(tv_dg14)              == True

    tv_dg15 = ef.DG15.load(bytes.fromhex('6F81A230819F300D06092A864886F70D010101050003818D00308189028181008130E120BB785A45D8D87E6F1A89EF4C6B655A555F58887DC6F78C293E71B028621B464C7B3123DF8896449ACB2A6E0219B7A43141BA617AE0E94CB5372EB6D964A1DBF2A43BD0CE659E962AC2CE9CEDF681CA1E3C74EA23C62D9ABFB81371D2602E39162EB578F9DED459C758EFD6A27A755B8C0E0E31E040D4D37A276939090203010001'))
    assert sod.ldsSecurityObject.contains(tv_dg15)              == False

    # DSC certificate check
    assert len(sod.dscCertificates) == 1
    with open(datafiles / 'dsc_de_0142fd5cf927.cer', "rb") as dsc:
        dsc = DocumentSignerCertificate.load(dsc.read())
        assert sod.dscCertificates[0].dump() == dsc.dump()

    # Verify signers info
    assert len(sod.signers)                          == 1
    assert sod.signers[0].version.native             == 'v1'
    assert sod.signers[0]['digest_algorithm'].native == { 'algorithm' :'sha256', 'parameters': None }
    assert sod.signers[0]['digest_algorithm'].native == sod.signedData.native['digest_algorithms'][0]
    assert len(sod.signers[0].signedAttributes)      == 2
    assert sod.signers[0].signedAttributes[0].native == { 'type' : 'content_type', 'values' : ['ldsSecurityObject'] }
    assert sod.signers[0].signedAttributes[1].native == {
        'type' : 'message_digest',
        'values' : [bytes.fromhex('B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6')]
    }

    assert len(sod.signers[0].signatureAlgorithm.native) == 2
    assert sod.signers[0].signatureAlgorithm.native      == {
        'algorithm' : 'rsassa_pss',
        'parameters' : {
            'hash_algorithm' : { 'algorithm' :'sha256', 'parameters': None },
            'mask_gen_algorithm' : {
                'algorithm' : 'mgf1',
                'parameters' : { 'algorithm' :'sha256', 'parameters': None }
            },
            'salt_length' : 32,
            'trailer_field' : 'trailer_field_bc'
        }
    }

    assert sod.signers[0].signature                == bytes.fromhex('761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
    assert sod.signers[0].native['unsigned_attrs'] is None

    # Check signers
    assert len(sod.signers) == 1
    assert sod.signers[0].version.native       == 'v1'
    assert type(sod.signers[0].sid.chosen)     == IssuerAndSerialNumber
    assert type(sod.signers[0].id)             == IssuerAndSerialNumber
    assert sod.signers[0].sid.native['issuer'] == {
        'country_name' : 'DE',
        'organization_name' : 'HJP Consulting',
        'organizational_unit_name' : 'Country Signer',
        'common_name' : 'HJP PB CS'
    }
    assert sod.signers[0].sid.native['issuer']        == sod.dscCertificates[0].issuer.native
    assert sod.signers[0].sid.native['serial_number'] == 1387230198055
    assert sod.signers[0].sid.native['serial_number'] == sod.dscCertificates[0].serial_number
    assert sod.signers[0].signingTime                 is None
    assert sod.signers[0].signature                   == bytes.fromhex('761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
    assert sod.signers[0].signedAttributes[0].native  == { 'type' : 'content_type', 'values' : ['ldsSecurityObject'] }
    assert sod.signers[0].signedAttributes[1].native  == {
        'type' : 'message_digest',
        'values' : [bytes.fromhex('B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6')]
    }
    assert sod.signers[0]['unsigned_attrs'].native    is None
    assert sod.signers[0].contentType                 == sod.signedData.contentType
    assert sod.signers[0].signedDigest                == bytes.fromhex('B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6')
    assert sod.signers[0].signatureAlgorithm.native   == {
        'algorithm' : 'rsassa_pss',
        'parameters' : {
            'hash_algorithm' : { 'algorithm' :'sha256', 'parameters': None },
            'mask_gen_algorithm' : {
                'algorithm' : 'mgf1',
                'parameters' : { 'algorithm' :'sha256', 'parameters': None }
            },
            'salt_length' : 32,
            'trailer_field' : 'trailer_field_bc'
        }
    }

    # Verify signed content hash and signer info signature
    h = sod.signers[0].contentHasher
    h.update(sod.signedData.content.dump())
    assert h.finalize() == sod.signers[0].signedDigest
    assert sod.getDscCertificate(sod.signers[0]).dump() == sod.dscCertificates[0].dump()
    sod.signers[0].verifySignedAttributes(sod.dscCertificates[0])

    # Verify SOD signature
    sod.verify(sod.signers[0], sod.dscCertificates[0])

    # Test vector taken from https://www.etsi.org/
    # https://www.etsi.org/deliver/etsi_tr/103200_103299/103200/01.01.01_60/tr_103200v010101p.pdf
    # https://docbox.etsi.org/MTS/MTS/05-CONTRIBUTIONS/2011/MTS(11)0044_DMIMTS-00127_ePassport_Prototype_Platform.zip
    # ePassport_Data/CFG/DFLT/EACAA/EF_SOD.bin
    tv_sod = bytes.fromhex('778207903082078C06092A864886F70D010702A082077D30820779020103310F300D06096086480165030402010500308201120606678108010101A0820106048201023081FF020100300D060960864801650304020105003081EA3025020101042051B6FC0EF1946F3A86D2A4C9557C5D8ECFF13113B4131089C5C48BF7291FFDF530250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420A1A7B2285B954DD053253C1D851709F6380731176CC9EB1123546439C704108A302502010F04205265ECB286F406D93EC5B8965659D45450D8DA1A97575DEF4EFC7303C7408730302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA082044D308204493082027DA00302010202060130846F2B3E304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203047310B3009060355040613024445310D300B060355040A0C044554534931173015060355040B0C0E436F756E747279205369676E65723110300E06035504030C0745545349204353301E170D3131303631323135313835365A170D3132303630363135313835365A3048310B3009060355040613024445310D300B060355040A0C044554534931183016060355040B0C0F446F63756D656E74205369676E65723110300E06035504030C074554534920445330820122300D06092A864886F70D01010105000382010F003082010A0282010100D986CFA346CDE37F6F900ADDAE5D91CA955FF02AAB8AD8BBF4EF6D2A7BD25EB67F6EA56F2C4F2BEA026E66569C9E242607B19ECC84F8E441CE973D8BD76F7C4D2897E1D8CBF937C29272EF68FB33E46CBF02969CACD84A778F6FDBEE5C0C06E5FF5BAEF3BB0EF2FC2B66CCF768F0970E9A5D93D5B506C31B41BF6AFB0A3840DF287EE3BEE348FA05D47F855486851A6D966E2DC002EF028FA2491BA25783C74D5CE839B2C6F6A43A84502353C0C0C08F027A4AD1FB5431FC11D097EF228B5721D02C264A7F961A8C441F266BC755FF36C3E442DD674909FFD21129623707AFC0F1F701BF1C586CB6FDF5321F50ACDE6241E4684FEAB8D7958843656358AB3D510203010001A3523050301F0603551D23041830168014CEA56178E7A1585B3AEF1E25EF9EC82940158D10301D0603551D0E04160414731FE7AEC52D7A75624F8DC4D794CEA4709EFB5A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201200382018100B15A5DB7E7280F1A15070817E6E877079741910A33C7C99F783CB61003A45120B6348545FD588C676D96BBE9AF609BDEE9D633A1C1B5C302F4B24C299C5B27DA68A84756569186EC9C417F40B19BC6F9639FC0B7DEFA77526DABBCE014D9C3578718373CB4289D0365F2B78B52EB274198F4820C33EC0496EBFB16960D17A49EBA1859E4A0737EF6C91AA776B712DB2DF9A44933FC5AFA96E532ABF896C1C1CD0076A6AF0746FEDC212C8F41B257F45626C064EACD3FC244232C0689768F0A30C0FA4D46422736AA26C1FA6D880623EB86C04920312D72B044985AC03A0A6EA3F4EFF784C7FD62BB751D240E7A939DBFFAAE999FCB237643B3A032078D2471F78C38487A6860E0C1CD23B796E12484C32B737E13A0F44E3BAF632204440150F035C09B1827BF87692C766E93AFEC3616B984916BC43006EFA5BB92ACD25344095D276FB615E38D0311BB3B849FD0E5269B8B0A85E7FC649A4B5C2BFE05A3D22B3EEBA432F34D0883A6AED5E119CB030396714D19E4D93E006EDFF3DD6E177C40318201FA308201F602010130513047310B3009060355040613024445310D300B060355040A0C044554534931173015060355040B0C0E436F756E747279205369676E65723110300E06035504030C074554534920435302060130846F2B3E300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B07B3583840A50F05E0B0AC5C8310629314B377D2F843FC82110A3B072BE5227304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100599622056634871C86D5161CCA6AF851F14148E0E7EB79B1186DD6BEDF5BD0343EDB6C49B664E9FB459E742CA83358CE83E6B225A0CBFA7C3E9C6AF6D5BC2F4040DD47BF24CACB06FBDD933EEFAD360542656E1F65E0010B8EAE4DA084FC7B78ECB0CED647580BD1E8E2F8660252721E6DC8BD83A8EBE27F780FDBCBEA49D24C6A8A596BA4F4673A04409F2C1EA1CBC6802C9748DD5B2DF042391BA87650447C7E3BAD05553ACDEB96972E3907F425571D767F82219E02BB8839E7FEC9CFE07DCB88B5831A511383DADF5C7C0CB1CE1BD6C2B8B02C2C20DB27402DD3B0CE171993C417D065DD9A0B278E641CF51BABBCCA1128A400ED4AB7C0FD531E4D1E475C')
    sod = ef.SOD.load(tv_sod)
    assert sod.dump()                                                          == tv_sod
    assert len(sod.content.children)                                           == 2
    assert sod.content.native['content_type']                                  == 'signed_data'
    assert sod.content.native['content']['version']                            == 'v3'
    assert len(sod.content.native['content']['digest_algorithms'])             == 1
    assert sod.content.native['content']['digest_algorithms'][0]['algorithm']  == 'sha256'
    assert sod.content.native['content']['encap_content_info']['content_type'] == 'ldsSecurityObject'
    assert sod.signedData.contentType.native                                   == 'ldsSecurityObject'

    # LDS SecurityObject test
    assert sod.ldsSecurityObject.version.native                            == 'v0'
    assert sod.ldsSecurityObject.ldsVersion.native                         is None
    assert sod.ldsSecurityObject.dgHashAlgo['algorithm'].native            == 'sha256'
    assert sod.ldsSecurityObject.dgHashAlgo['parameters'].native           is None

    assert len(sod.ldsSecurityObject.dgHashes)                             == 6
    assert sod.ldsSecurityObject.dgHashes.native[0]['dataGroupNumber']     == 'EF.DG1'
    assert sod.ldsSecurityObject.dgHashes.children[0].number               == DataGroupNumber(1)
    assert sod.ldsSecurityObject.dgHashes.native[0]['dataGroupHashValue']  == bytes.fromhex('51B6FC0EF1946F3A86D2A4C9557C5D8ECFF13113B4131089C5C48BF7291FFDF5')
    assert sod.ldsSecurityObject.dgHashes.children[0].hash                 == bytes.fromhex('51B6FC0EF1946F3A86D2A4C9557C5D8ECFF13113B4131089C5C48BF7291FFDF5')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(1))     == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(1)).number  == DataGroupNumber(1)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(1)).hash    == bytes.fromhex('51B6FC0EF1946F3A86D2A4C9557C5D8ECFF13113B4131089C5C48BF7291FFDF5')
    assert sod.ldsSecurityObject.find(DataGroupNumber(1)).number           == DataGroupNumber(1)
    assert sod.ldsSecurityObject.find(DataGroupNumber(1)).hash             == bytes.fromhex('51B6FC0EF1946F3A86D2A4C9557C5D8ECFF13113B4131089C5C48BF7291FFDF5')

    assert sod.ldsSecurityObject.dgHashes.native[1]['dataGroupNumber']     == 'EF.DG2'
    assert sod.ldsSecurityObject.dgHashes.children[1].number               == DataGroupNumber(2)
    assert sod.ldsSecurityObject.dgHashes.native[1]['dataGroupHashValue']  == bytes.fromhex('A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E54745')
    assert sod.ldsSecurityObject.dgHashes.children[1].hash                 == bytes.fromhex('A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E54745')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(2))     == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(2)).number  == DataGroupNumber(2)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(2)).hash    == bytes.fromhex('A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E54745')
    assert sod.ldsSecurityObject.find(DataGroupNumber(2)).number           == DataGroupNumber(2)
    assert sod.ldsSecurityObject.find(DataGroupNumber(2)).hash             == bytes.fromhex('A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E54745')

    assert sod.ldsSecurityObject.dgHashes.native[2]['dataGroupNumber']     == 'EF.DG3'
    assert sod.ldsSecurityObject.dgHashes.children[2].number               == DataGroupNumber(3)
    assert sod.ldsSecurityObject.dgHashes.native[2]['dataGroupHashValue']  == bytes.fromhex('403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00')
    assert sod.ldsSecurityObject.dgHashes.children[2].hash                 == bytes.fromhex('403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(3))     == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(3)).number  == DataGroupNumber(3)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(3)).hash    == bytes.fromhex('403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00')
    assert sod.ldsSecurityObject.find(DataGroupNumber(3)).number           == DataGroupNumber(3)
    assert sod.ldsSecurityObject.find(DataGroupNumber(3)).hash            == bytes.fromhex('403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00')

    assert sod.ldsSecurityObject.dgHashes.native[3]['dataGroupNumber']     == 'EF.DG14'
    assert sod.ldsSecurityObject.dgHashes.children[3].number               == DataGroupNumber(14)
    assert sod.ldsSecurityObject.dgHashes.native[3]['dataGroupHashValue']  == bytes.fromhex('A1A7B2285B954DD053253C1D851709F6380731176CC9EB1123546439C704108A')
    assert sod.ldsSecurityObject.dgHashes.children[3].hash                 == bytes.fromhex('A1A7B2285B954DD053253C1D851709F6380731176CC9EB1123546439C704108A')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(14))    == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(14)).number == DataGroupNumber(14)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(14)).hash   == bytes.fromhex('A1A7B2285B954DD053253C1D851709F6380731176CC9EB1123546439C704108A')
    assert sod.ldsSecurityObject.find(DataGroupNumber(14)).number          == DataGroupNumber(14)
    assert sod.ldsSecurityObject.find(DataGroupNumber(14)).hash            == bytes.fromhex('A1A7B2285B954DD053253C1D851709F6380731176CC9EB1123546439C704108A')

    assert sod.ldsSecurityObject.dgHashes.native[4]['dataGroupNumber']     == 'EF.DG15'
    assert sod.ldsSecurityObject.dgHashes.children[4].number               == DataGroupNumber(15)
    assert sod.ldsSecurityObject.dgHashes.native[4]['dataGroupHashValue']  == bytes.fromhex('5265ECB286F406D93EC5B8965659D45450D8DA1A97575DEF4EFC7303C7408730')
    assert sod.ldsSecurityObject.dgHashes.children[4].hash                 == bytes.fromhex('5265ECB286F406D93EC5B8965659D45450D8DA1A97575DEF4EFC7303C7408730')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(14))    == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(15)).number == DataGroupNumber(15)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(15)).hash   == bytes.fromhex('5265ECB286F406D93EC5B8965659D45450D8DA1A97575DEF4EFC7303C7408730')
    assert sod.ldsSecurityObject.find(DataGroupNumber(15)).number          == DataGroupNumber(15)
    assert sod.ldsSecurityObject.find(DataGroupNumber(15)).hash            == bytes.fromhex('5265ECB286F406D93EC5B8965659D45450D8DA1A97575DEF4EFC7303C7408730')

    assert sod.ldsSecurityObject.dgHashes.native[5]['dataGroupNumber']     == 'EF.DG4'
    assert sod.ldsSecurityObject.dgHashes.children[5].number               == DataGroupNumber(4)
    assert sod.ldsSecurityObject.dgHashes.native[5]['dataGroupHashValue']  == bytes.fromhex('4C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17B')
    assert sod.ldsSecurityObject.dgHashes.children[5].hash                 == bytes.fromhex('4C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17B')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(4))     == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(4)).number  == DataGroupNumber(4)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(4)).hash    == bytes.fromhex('4C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17B')
    assert sod.ldsSecurityObject.find(DataGroupNumber(4)).number           == DataGroupNumber(4)
    assert sod.ldsSecurityObject.find(DataGroupNumber(4)).hash             == bytes.fromhex('4C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17B')

    hasher = sod.ldsSecurityObject.getDgHasher()
    assert hasher.algorithm.name == 'sha256'
    tv_dg1 = ef.DG1.load(bytes.fromhex('615B5F1F58503C443C3C4D55535445524D414E4E3C3C4552494B413C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C433131543030324A4D34443C3C3936303831323246313331303331373C3C3C3C3C3C3C3C3C3C3C3C3C3C3C36'))
    hasher.update(tv_dg1.dump())
    assert sod.ldsSecurityObject.find(DataGroupNumber(1)).hash == hasher.finalize()
    assert sod.ldsSecurityObject.contains(tv_dg1)              == True

    hasher = sod.ldsSecurityObject.getDgHasher()
    assert hasher.algorithm.name == 'sha256'
    tv_dg14 = ef.DG14.load(bytes.fromhex('6E82014A3182014630820122060904007F000702020102308201133081D406072A8648CE3D02013081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101033A00047BEAAD1C2738A816525EE6B96823028B975E6EA1A2284105A6AAE2A42A2D83EFF9FAC24EE4ECCFCB1214AB3AD10C01782D465532B8D27E29300F060A04007F00070202030201020101300D060804007F0007020202020101'))
    hasher.update(tv_dg14.dump())
    assert sod.ldsSecurityObject.find(DataGroupNumber(14)).hash == hasher.finalize()
    assert sod.ldsSecurityObject.contains(tv_dg14)              == True

    hasher = sod.ldsSecurityObject.getDgHasher()
    assert hasher.algorithm.name == 'sha256'
    tv_dg15 = ef.DG15.load(bytes.fromhex('6F81A230819F300D06092A864886F70D010101050003818D003081890281810095BDA8143635678427038D225E6F398B327F8AF02647B65C36E9FA8F4E7F8156364A231326F1EC1B9641B78822EC3014656D375C5F60641717F40F40B699DE3CCCB054550DD6DF2640022B9352701F2AB757E9A20FA605D309B6DDD7201F23CFDACC9EE299F187E9E71B650483DC4F6BC109F8FE8A2C2854C784057EE0E6F7670203010001'))
    hasher.update(tv_dg15.dump())
    assert sod.ldsSecurityObject.find(DataGroupNumber(15)).hash == hasher.finalize()
    assert sod.ldsSecurityObject.contains(tv_dg15)              == True

    # DSC certificate check
    assert len(sod.dscCertificates) == 1
    with open(datafiles / 'dsc_de_0130846f2b3e.cer', "rb") as dsc:
        dsc = DocumentSignerCertificate.load(dsc.read())
        assert sod.dscCertificates[0].dump() == dsc.dump()

    # Verify signers info
    assert len(sod.content.native['content']['signer_infos'])                    == 1
    assert sod.content.native['content']['signer_infos'][0]['version']           == 'v1'
    assert sod.content.native['content']['signer_infos'][0]['digest_algorithm']  == { 'algorithm' :'sha256', 'parameters': None }
    assert sod.content.native['content']['signer_infos'][0]['digest_algorithm']  == sod.content.native['content']['digest_algorithms'][0]
    assert len(sod.content.native['content']['signer_infos'][0]['signed_attrs']) == 2
    assert sod.content.native['content']['signer_infos'][0]['signed_attrs'][0]   == { 'type' : 'content_type', 'values' : ['ldsSecurityObject'] }
    assert sod.content.native['content']['signer_infos'][0]['signed_attrs'][1]   == {
        'type' : 'message_digest',
        'values' : [bytes.fromhex('B07B3583840A50F05E0B0AC5C8310629314B377D2F843FC82110A3B072BE5227')]
    }

    assert len(sod.content.native['content']['signer_infos'][0]['signature_algorithm']) == 2
    assert sod.content.native['content']['signer_infos'][0]['signature_algorithm']      == {
        'algorithm' : 'rsassa_pss',
        'parameters' : {
            'hash_algorithm' : { 'algorithm' :'sha256', 'parameters': None },
            'mask_gen_algorithm' : {
                'algorithm' : 'mgf1',
                'parameters' : { 'algorithm' :'sha256', 'parameters': None }
            },
            'salt_length' : 32,
            'trailer_field' : 'trailer_field_bc'
        }
    }

    assert sod.content.native['content']['signer_infos'][0]['signature'] == bytes.fromhex('599622056634871C86D5161CCA6AF851F14148E0E7EB79B1186DD6BEDF5BD0343EDB6C49B664E9FB459E742CA83358CE83E6B225A0CBFA7C3E9C6AF6D5BC2F4040DD47BF24CACB06FBDD933EEFAD360542656E1F65E0010B8EAE4DA084FC7B78ECB0CED647580BD1E8E2F8660252721E6DC8BD83A8EBE27F780FDBCBEA49D24C6A8A596BA4F4673A04409F2C1EA1CBC6802C9748DD5B2DF042391BA87650447C7E3BAD05553ACDEB96972E3907F425571D767F82219E02BB8839E7FEC9CFE07DCB88B5831A511383DADF5C7C0CB1CE1BD6C2B8B02C2C20DB27402DD3B0CE171993C417D065DD9A0B278E641CF51BABBCCA1128A400ED4AB7C0FD531E4D1E475C')
    assert sod.content.native['content']['signer_infos'][0]['unsigned_attrs'] is None

    # Check signers
    assert len(sod.signers) == 1
    assert sod.signers[0].version.native       == 'v1'
    assert type(sod.signers[0].sid.chosen)     == IssuerAndSerialNumber
    assert type(sod.signers[0].id)             == IssuerAndSerialNumber
    assert sod.signers[0].sid.native['issuer'] == {
        'country_name' : 'DE',
        'organization_name' : 'ETSI',
        'organizational_unit_name' : 'Country Signer',
        'common_name' : 'ETSI CS'
    }
    assert sod.signers[0].sid.native['issuer']        == sod.dscCertificates[0].issuer.native
    assert sod.signers[0].sid.native['serial_number'] == 1307891936062
    assert sod.signers[0].sid.native['serial_number'] == sod.dscCertificates[0].serial_number
    assert sod.signers[0].signingTime                 is None
    assert sod.signers[0].signature                   == bytes.fromhex('599622056634871c86d5161cca6af851f14148e0e7eb79b1186dd6bedf5bd0343edb6c49b664e9fb459e742ca83358ce83e6b225a0cbfa7c3e9c6af6d5bc2f4040dd47bf24cacb06fbdd933eefad360542656e1f65e0010b8eae4da084fc7b78ecb0ced647580bd1e8e2f8660252721e6dc8bd83a8ebe27f780fdbcbea49d24c6a8a596ba4f4673a04409f2c1ea1cbc6802c9748dd5b2df042391ba87650447c7e3bad05553acdeb96972e3907f425571d767f82219e02bb8839e7fec9cfe07dcb88b5831a511383dadf5c7c0cb1ce1bd6c2b8b02c2c20db27402dd3b0ce171993c417d065dd9a0b278e641cf51babbcca1128a400ed4ab7c0fd531e4d1e475c')
    assert sod.signers[0].signedAttributes[0].native  == { 'type' : 'content_type', 'values' : ['ldsSecurityObject'] }
    assert sod.signers[0].signedAttributes[1].native  == {
        'type' : 'message_digest',
        'values' : [bytes.fromhex('b07b3583840a50f05e0b0ac5c8310629314b377d2f843fc82110a3b072be5227')]
    }
    assert sod.signers[0]['unsigned_attrs'].native    is None
    assert sod.signers[0].contentType                 == sod.signedData.contentType
    assert sod.signers[0].signedDigest                == bytes.fromhex('b07b3583840a50f05e0b0ac5c8310629314b377d2f843fc82110a3b072be5227')
    assert sod.signers[0].signatureAlgorithm.native   == {
        'algorithm' : 'rsassa_pss',
        'parameters' : {
            'hash_algorithm' : { 'algorithm' :'sha256', 'parameters': None },
            'mask_gen_algorithm' : {
                'algorithm' : 'mgf1',
                'parameters' : { 'algorithm' :'sha256', 'parameters': None }
            },
            'salt_length' : 32,
            'trailer_field' : 'trailer_field_bc'
        }
    }

    # Verify signed content hash and signer info signature
    h = sod.signers[0].contentHasher
    h.update(sod.signedData.content.dump())
    assert h.finalize() == sod.signers[0].signedDigest
    assert sod.getDscCertificate(sod.signers[0]).dump() == sod.dscCertificates[0].dump()
    sod.signers[0].verifySignedAttributes(sod.dscCertificates[0])

    # Verify SOD signature
    sod.verify(sod.signers[0], sod.dscCertificates[0])

    # Test vector taken from German BSI TR-03105-5 ReferenceDataSet and was modified to have OID tag 1.2.840.113549.1.7.1 - id-data content type for LDS security object to
    # https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03105/BSI_TR-03105-5_ReferenceDataSet_zip.html
    # EF_SOD.bin
    tv_sod = bytes.fromhex('778207903082078c06092a864886f70d010702a082077d30820779020103310f300d060960864801650304020105003081ec06092a864886f70d010701a081de0481db3081d8020100300d060960864801650304020105003081c3302502010104204170ca879fce6a22ffef1567ff88079f415c66ead250ab5f23781ac2cdbf42b630250201020420a9a1b09dfd598087ab3fce4ae2ec65b1a1525bd258bfc27df4419f8a65e5474530250201030420403e4d17c26ebc832411898161d8fd5d99c58ee865cb3759b529aa782c7ede00302502010e0420cf5004ffccd64e1a8bd3a42fd53814ec3d4481640be1906d0ecfeb016ef6a6ae302502010404204c7a0f0ddaa473123834f1b0713ed9453d1d1d58bce447fb1736d40a0761c17ba08204653082046130820295a00302010202060142fd5cf927304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a2030201203053310b300906035504061302444531173015060355040a0c0e484a5020436f6e73756c74696e6731173015060355040b0c0e436f756e747279205369676e65723112301006035504030c09484a50205042204353301e170d3133313231363231343331385a170d3134313231313231343331385a3054310b300906035504061302444531173015060355040a0c0e484a5020436f6e73756c74696e6731183016060355040b0c0f446f63756d656e74205369676e65723112301006035504030c09484a5020504220445330820122300d06092a864886f70d01010105000382010f003082010a02820101009e7cbb065377041232915a044dd3adc2199ad4c14bc8e58c24a899dbd62a984eeae2a0006c1d53439246a67a9964d759bc7b9426ce6c4c078363306cf66645f12f39d950fe2c04100e6ff53c310b52f74cd1ed89931496f376d384ab604a570129445f015fcc3595e161b7c591cb5206bc16477d8cdec09480dbf6262696f62970da0978807dba330ee777bf54d471ae1eb257090f1379e198a2d1503344847347be46764fa00c4e93bacd32143b2e04c6c369cece7943fd414521849533f9cdb985e42767f1dd792e7efed3651e3c75df868fa2101df45cd5d3d955b23a88dd30a752f4fb9f4e84b518e0ca0f8f2bace65d61f98115a0ea88dd3a3416017ca30203010001a3523050301f0603551d230418301680141e4d57560c12902366a8fde11408a37f70eb7d65301d0603551d0e04160414831c30be878fdf57273010e5b38950e576f7b08a300e0603551d0f0101ff040403020780304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003820181002984dc43028839bb24786a4c9c9c37e76368ff6264707970e5b00f7934840904ed90e34b018d5d634d7536e49afe7b0e872f5d093e6d11bf31c910686a9106f9f773f59c57aeff983de6335b5cb403e0ff7d3055f09948878f8be1bc184f2a03c82c14097fc19deddccf61a2eae6f8bf1a64be4c0253ce0bc35ad41e10d6ff08c1ee872349e8d02a722f48144cab665d0fadf9db3b36bfb2b15ae4a3b13dc4cf64133b599cdb3af8a365ac6228096899fea8d56a24f90da72b3e95b97fd82c4b8ef9cbb499c3d9f09053a5fddd51e94a13a004530d74f7dd1b0c88163f9bfa098923dc81d247d75e33cac3c7e27aeac627b99ab18e6b03d38260e2dccfa1d638d17614773bc13eba0d53e2e3e9a202e0742c25df471072cda2a88ba2b25648970bc31132de84f702abbc98740b4fee7c66cd149755a763b801dcf9dc1b52191a3acc514244c51d297f35e5aea328b8641b33d54dc7c50d2466f9dddce98a75f276d48d614b6c4fa675c2017824bed7cc27b46fcbe5b82ce4b433e34aaed2ebee3182020930820205020101305d3053310b300906035504061302444531173015060355040a0c0e484a5020436f6e73756c74696e6731173015060355040b0c0e436f756e747279205369676e65723112301006035504030c09484a5020504220435302060142fd5cf927300d06096086480165030402010500a04b301806092a864886f70d010903310b06092a864886f70d010701302f06092a864886f70d01090431220420b46a0d05e280f398efeeebff67e78c736add15e75670b1ad4c6c534e8187b9d6304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012004820100761106e9fbd2ed1b2f75027daf13975a4c7adfc54d675d2dd2bba762bc073d9288af4b1b87ba7987d53fa1d321d1943f58573f4913424e2bcdd080c2d8927a985be2bdcaf6b8fe21ec99d8227f052ed118b7eae6029f57889ca723912076916355068ebbcf46f19c3fbb49dcf1e9f3b10df11e270fac11bc6d1e3c5adf68e0e46381a45f737e91ee9f889db6d418aa2c6c3213c47fbc2787f0134384b343cc921a9a03878eba79ba00901115495942c3e7b0e4da09e0916c172228ad28d9dbec915f32e58d7431480443030c2c3d1def840223fed41a92c5b30aa2ce9ed346cbb8bb172a2eff73e0b8cfec89071a07dc62627421f808da541a58a1a572e7583f')
    sod = ef.SOD.load(tv_sod)
    sod = ef.SOD.load(tv_sod, strict = False)

    assert sod.dump()                                                          == tv_sod
    assert len(sod.content.children)                                           == 2
    assert sod.content.native['content_type']                                  == 'signed_data'
    assert sod.content.native['content']['version']                            == 'v3'
    assert len(sod.content.native['content']['digest_algorithms'])             == 1
    assert sod.content.native['content']['digest_algorithms'][0]['algorithm']  == 'sha256'
    assert sod.content.native['content']['encap_content_info']['content_type'] == 'data'
    assert sod.signedData.contentType.native                                   == 'data'

    # LDS SecurityObject test
    assert sod.ldsSecurityObject.version.native                            == 'v0'
    assert sod.ldsSecurityObject.ldsVersion.native                         is None
    assert sod.ldsSecurityObject.dgHashAlgo['algorithm'].native            == 'sha256'
    assert sod.ldsSecurityObject.dgHashAlgo['parameters'].native           is None

    assert len(sod.ldsSecurityObject.dgHashes)                             == 5
    assert sod.ldsSecurityObject.dgHashes.native[0]['dataGroupNumber']     == 'EF.DG1'
    assert sod.ldsSecurityObject.dgHashes.children[0].number               == DataGroupNumber(1)
    assert sod.ldsSecurityObject.dgHashes.native[0]['dataGroupHashValue']  == bytes.fromhex('4170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B6')
    assert sod.ldsSecurityObject.dgHashes.children[0].hash                 == bytes.fromhex('4170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B6')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(1))     == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(1)).number  == DataGroupNumber(1)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(1)).hash    == bytes.fromhex('4170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B6')
    assert sod.ldsSecurityObject.find(DataGroupNumber(1)).number           == DataGroupNumber(1)
    assert sod.ldsSecurityObject.find(DataGroupNumber(1)).hash             == bytes.fromhex('4170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B6')

    assert sod.ldsSecurityObject.dgHashes.native[1]['dataGroupNumber']     == 'EF.DG2'
    assert sod.ldsSecurityObject.dgHashes.children[1].number               == DataGroupNumber(2)
    assert sod.ldsSecurityObject.dgHashes.native[1]['dataGroupHashValue']  == bytes.fromhex('A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E54745')
    assert sod.ldsSecurityObject.dgHashes.children[1].hash                 == bytes.fromhex('A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E54745')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(2))     == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(2)).number  == DataGroupNumber(2)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(2)).hash    == bytes.fromhex('A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E54745')
    assert sod.ldsSecurityObject.find(DataGroupNumber(2)).number           == DataGroupNumber(2)
    assert sod.ldsSecurityObject.find(DataGroupNumber(2)).hash             == bytes.fromhex('A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E54745')

    assert sod.ldsSecurityObject.dgHashes.native[2]['dataGroupNumber']     == 'EF.DG3'
    assert sod.ldsSecurityObject.dgHashes.children[2].number               == DataGroupNumber(3)
    assert sod.ldsSecurityObject.dgHashes.native[2]['dataGroupHashValue']  == bytes.fromhex('403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00')
    assert sod.ldsSecurityObject.dgHashes.children[2].hash                 == bytes.fromhex('403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(3))     == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(3)).number  == DataGroupNumber(3)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(3)).hash    == bytes.fromhex('403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00')
    assert sod.ldsSecurityObject.find(DataGroupNumber(3)).number           == DataGroupNumber(3)
    assert sod.ldsSecurityObject.find(DataGroupNumber(3)).hash             == bytes.fromhex('403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00')

    assert sod.ldsSecurityObject.dgHashes.native[3]['dataGroupNumber']     == 'EF.DG14'
    assert sod.ldsSecurityObject.dgHashes.children[3].number               == DataGroupNumber(14)
    assert sod.ldsSecurityObject.dgHashes.native[3]['dataGroupHashValue']  == bytes.fromhex('CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE')
    assert sod.ldsSecurityObject.dgHashes.children[3].hash                 == bytes.fromhex('CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(14))    == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(14)).number == DataGroupNumber(14)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(14)).hash   == bytes.fromhex('CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE')
    assert sod.ldsSecurityObject.find(DataGroupNumber(14)).number          == DataGroupNumber(14)
    assert sod.ldsSecurityObject.find(DataGroupNumber(14)).hash            == bytes.fromhex('CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE')

    assert sod.ldsSecurityObject.dgHashes.native[4]['dataGroupNumber']     == 'EF.DG4'
    assert sod.ldsSecurityObject.dgHashes.children[4].number               == DataGroupNumber(4)
    assert sod.ldsSecurityObject.dgHashes.native[4]['dataGroupHashValue']  == bytes.fromhex('4C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17B')
    assert sod.ldsSecurityObject.dgHashes.children[4].hash                 == bytes.fromhex('4C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17B')
    assert sod.ldsSecurityObject.dgHashes.contains(DataGroupNumber(4))     == True
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(4)).number  == DataGroupNumber(4)
    assert sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(4)).hash    == bytes.fromhex('4C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17B')
    assert sod.ldsSecurityObject.find(DataGroupNumber(4)).number           == DataGroupNumber(4)
    assert sod.ldsSecurityObject.find(DataGroupNumber(4)).hash             == bytes.fromhex('4C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17B')

    hasher = sod.ldsSecurityObject.getDgHasher()
    assert hasher.algorithm.name == 'sha256'
    tv_dg1 = ef.DG1.load(bytes.fromhex('615B5F1F58503C443C3C4D55535445524D414E4E3C3C4552494B413C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C433131543030324A4D34443C3C3936303831323246323331303331343C3C3C3C3C3C3C3C3C3C3C3C3C3C3C34'))
    hasher.update(tv_dg1.dump())
    assert sod.ldsSecurityObject.find(DataGroupNumber(1)).hash == hasher.finalize()
    assert sod.ldsSecurityObject.contains(tv_dg1)              == True

    hasher = sod.ldsSecurityObject.getDgHasher()
    assert hasher.algorithm.name == 'sha256'
    tv_dg14 = ef.DG14.load(bytes.fromhex('6E82014A3182014630820122060904007F000702020102308201133081D406072A8648CE3D02013081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101033A0004A847F020F71DF33D386BE7C9223A354D6AC7727018B26E281C6FFB96A83B142AAF303C23F2BCF2CDE4706C14E45914A9BE42C15BCB67A01F300F060A04007F00070202030201020101300D060804007F0007020202020101'))
    hasher.update(tv_dg14.dump())
    assert sod.ldsSecurityObject.find(DataGroupNumber(14)).hash == hasher.finalize()
    assert sod.ldsSecurityObject.contains(tv_dg14)              == True

    tv_dg15 = ef.DG15.load(bytes.fromhex('6F81A230819F300D06092A864886F70D010101050003818D00308189028181008130E120BB785A45D8D87E6F1A89EF4C6B655A555F58887DC6F78C293E71B028621B464C7B3123DF8896449ACB2A6E0219B7A43141BA617AE0E94CB5372EB6D964A1DBF2A43BD0CE659E962AC2CE9CEDF681CA1E3C74EA23C62D9ABFB81371D2602E39162EB578F9DED459C758EFD6A27A755B8C0E0E31E040D4D37A276939090203010001'))
    assert sod.ldsSecurityObject.contains(tv_dg15)              == False

    # DSC certificate check
    assert len(sod.dscCertificates) == 1
    with open(datafiles / 'dsc_de_0142fd5cf927.cer', "rb") as dsc:
        dsc = DocumentSignerCertificate.load(dsc.read())
        assert sod.dscCertificates[0].dump() == dsc.dump()

    # Verify signers info
    assert len(sod.signers)                          == 1
    assert sod.signers[0].version.native             == 'v1'
    assert sod.signers[0]['digest_algorithm'].native == { 'algorithm' :'sha256', 'parameters': None }
    assert sod.signers[0]['digest_algorithm'].native == sod.signedData.native['digest_algorithms'][0]
    assert len(sod.signers[0].signedAttributes)      == 2
    assert sod.signers[0].signedAttributes[0].native == { 'type' : 'content_type', 'values' : ['data'] }
    assert sod.signers[0].signedAttributes[1].native == {
        'type' : 'message_digest',
        'values' : [bytes.fromhex('B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6')]
    }

    assert len(sod.signers[0].signatureAlgorithm.native) == 2
    assert sod.signers[0].signatureAlgorithm.native      == {
        'algorithm' : 'rsassa_pss',
        'parameters' : {
            'hash_algorithm' : { 'algorithm' :'sha256', 'parameters': None },
            'mask_gen_algorithm' : {
                'algorithm' : 'mgf1',
                'parameters' : { 'algorithm' :'sha256', 'parameters': None }
            },
            'salt_length' : 32,
            'trailer_field' : 'trailer_field_bc'
        }
    }

    assert sod.signers[0].signature                == bytes.fromhex('761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
    assert sod.signers[0].native['unsigned_attrs'] is None

    # Check signers
    assert len(sod.signers) == 1
    assert sod.signers[0].version.native       == 'v1'
    assert type(sod.signers[0].sid.chosen)     == IssuerAndSerialNumber
    assert type(sod.signers[0].id)             == IssuerAndSerialNumber
    assert sod.signers[0].sid.native['issuer'] == {
        'country_name' : 'DE',
        'organization_name' : 'HJP Consulting',
        'organizational_unit_name' : 'Country Signer',
        'common_name' : 'HJP PB CS'
    }
    assert sod.signers[0].sid.native['issuer']        == sod.dscCertificates[0].issuer.native
    assert sod.signers[0].sid.native['serial_number'] == 1387230198055
    assert sod.signers[0].sid.native['serial_number'] == sod.dscCertificates[0].serial_number
    assert sod.signers[0].signingTime                 is None
    assert sod.signers[0].signature                   == bytes.fromhex('761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
    assert sod.signers[0].signedAttributes[0].native  == { 'type' : 'content_type', 'values' : ['data'] }
    assert sod.signers[0].signedAttributes[1].native  == {
        'type' : 'message_digest',
        'values' : [bytes.fromhex('B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6')]
    }
    assert sod.signers[0]['unsigned_attrs'].native    is None
    assert sod.signers[0].contentType                 == sod.signedData.contentType
    assert sod.signers[0].signedDigest                == bytes.fromhex('B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6')
    assert sod.signers[0].signatureAlgorithm.native   == {
        'algorithm' : 'rsassa_pss',
        'parameters' : {
            'hash_algorithm' : { 'algorithm' :'sha256', 'parameters': None },
            'mask_gen_algorithm' : {
                'algorithm' : 'mgf1',
                'parameters' : { 'algorithm' :'sha256', 'parameters': None }
            },
            'salt_length' : 32,
            'trailer_field' : 'trailer_field_bc'
        }
    }

    # Verify signed content hash and signer info signature
    h = sod.signers[0].contentHasher
    h.update(sod.signedData.content.dump())
    assert h.finalize() == sod.signers[0].signedDigest
    assert sod.getDscCertificate(sod.signers[0]).dump() == sod.dscCertificates[0].dump()
    
    # Skip signature verification because signed atributes for content_type was changed
    # sod.signers[0].verifySignedAttributes(sod.dscCertificates[0])
    # sod.verify(sod.signers[0], sod.dscCertificates[0])

@pytest.mark.depends(on=['test_sod'])
def test_fuzz_sod():
    with pytest.raises(ef.sod.SODError, match=r"Invalid content type: '1.2.840.113549.1.8.2', expected 'signed_data'"):
        # Test exception is raised when root content type is '1.2.840.113549.1.8.2' and not 'signed_data'
        tv_sod = bytes.fromhex('7782078A3082078606092A864886F70D010802A082077730820773020103310F300D060960864801650304020105003081E90606678108010101A081DE0481DB3081D8020100300D060960864801650304020105003081C3302502010104204170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B630250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA08204653082046130820295A00302010202060142FD5CF927304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A50205042204353301E170D3133313231363231343331385A170D3134313231313231343331385A3054310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731183016060355040B0C0F446F63756D656E74205369676E65723112301006035504030C09484A5020504220445330820122300D06092A864886F70D01010105000382010F003082010A02820101009E7CBB065377041232915A044DD3ADC2199AD4C14BC8E58C24A899DBD62A984EEAE2A0006C1D53439246A67A9964D759BC7B9426CE6C4C078363306CF66645F12F39D950FE2C04100E6FF53C310B52F74CD1ED89931496F376D384AB604A570129445F015FCC3595E161B7C591CB5206BC16477D8CDEC09480DBF6262696F62970DA0978807DBA330EE777BF54D471AE1EB257090F1379E198A2D1503344847347BE46764FA00C4E93BACD32143B2E04C6C369CECE7943FD414521849533F9CDB985E42767F1DD792E7EFED3651E3C75DF868FA2101DF45CD5D3D955B23A88DD30A752F4FB9F4E84B518E0CA0F8F2BACE65D61F98115A0EA88DD3A3416017CA30203010001A3523050301F0603551D230418301680141E4D57560C12902366A8FDE11408A37F70EB7D65301D0603551D0E04160414831C30BE878FDF57273010E5B38950E576F7B08A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012003820181002984DC43028839BB24786A4C9C9C37E76368FF6264707970E5B00F7934840904ED90E34B018D5D634D7536E49AFE7B0E872F5D093E6D11BF31C910686A9106F9F773F59C57AEFF983DE6335B5CB403E0FF7D3055F09948878F8BE1BC184F2A03C82C14097FC19DEDDCCF61A2EAE6F8BF1A64BE4C0253CE0BC35AD41E10D6FF08C1EE872349E8D02A722F48144CAB665D0FADF9DB3B36BFB2B15AE4A3B13DC4CF64133B599CDB3AF8A365AC6228096899FEA8D56A24F90DA72B3E95B97FD82C4B8EF9CBB499C3D9F09053A5FDDD51E94A13A004530D74F7DD1B0C88163F9BFA098923DC81D247D75E33CAC3C7E27AEAC627B99AB18E6B03D38260E2DCCFA1D638D17614773BC13EBA0D53E2E3E9A202E0742C25DF471072CDA2A88BA2B25648970BC31132DE84F702ABBC98740B4FEE7C66CD149755A763B801DCF9DC1B52191A3ACC514244C51D297F35E5AEA328B8641B33D54DC7C50D2466F9DDDCE98A75F276D48D614B6C4FA675C2017824BED7CC27B46FCBE5B82CE4B433E34AAED2EBEE3182020630820202020101305D3053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A5020504220435302060142FD5CF927300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
        sod = ef.SOD.load(tv_sod)

    with pytest.raises(ef.sod.SODError, match=r'Error parsing asn1crypto.cms.DigestAlgorithms - tag should have been 17, but 16 was found\n    while parsing asn1crypto.cms.SignedAndEnvelopedData\n    while parsing pymrtd.ef.sod.SODContentInfo\n    while parsing pymrtd.ef.sod.SOD'):
        # Test exception is raised when root content type is ''1.2.840.113549.1.7.4''
        tv_sod = bytes.fromhex('7782078A3082078606092A864886F70D010704A082077730820773020103310F300D060960864801650304020105003081E90606678108010101A081DE0481DB3081D8020100300D060960864801650304020105003081C3302502010104204170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B630250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA08204653082046130820295A00302010202060142FD5CF927304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A50205042204353301E170D3133313231363231343331385A170D3134313231313231343331385A3054310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731183016060355040B0C0F446F63756D656E74205369676E65723112301006035504030C09484A5020504220445330820122300D06092A864886F70D01010105000382010F003082010A02820101009E7CBB065377041232915A044DD3ADC2199AD4C14BC8E58C24A899DBD62A984EEAE2A0006C1D53439246A67A9964D759BC7B9426CE6C4C078363306CF66645F12F39D950FE2C04100E6FF53C310B52F74CD1ED89931496F376D384AB604A570129445F015FCC3595E161B7C591CB5206BC16477D8CDEC09480DBF6262696F62970DA0978807DBA330EE777BF54D471AE1EB257090F1379E198A2D1503344847347BE46764FA00C4E93BACD32143B2E04C6C369CECE7943FD414521849533F9CDB985E42767F1DD792E7EFED3651E3C75DF868FA2101DF45CD5D3D955B23A88DD30A752F4FB9F4E84B518E0CA0F8F2BACE65D61F98115A0EA88DD3A3416017CA30203010001A3523050301F0603551D230418301680141E4D57560C12902366A8FDE11408A37F70EB7D65301D0603551D0E04160414831C30BE878FDF57273010E5B38950E576F7B08A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012003820181002984DC43028839BB24786A4C9C9C37E76368FF6264707970E5B00F7934840904ED90E34B018D5D634D7536E49AFE7B0E872F5D093E6D11BF31C910686A9106F9F773F59C57AEFF983DE6335B5CB403E0FF7D3055F09948878F8BE1BC184F2A03C82C14097FC19DEDDCCF61A2EAE6F8BF1A64BE4C0253CE0BC35AD41E10D6FF08C1EE872349E8D02A722F48144CAB665D0FADF9DB3B36BFB2B15AE4A3B13DC4CF64133B599CDB3AF8A365AC6228096899FEA8D56A24F90DA72B3E95B97FD82C4B8EF9CBB499C3D9F09053A5FDDD51E94A13A004530D74F7DD1B0C88163F9BFA098923DC81D247D75E33CAC3C7E27AEAC627B99AB18E6B03D38260E2DCCFA1D638D17614773BC13EBA0D53E2E3E9A202E0742C25DF471072CDA2A88BA2B25648970BC31132DE84F702ABBC98740B4FEE7C66CD149755A763B801DCF9DC1B52191A3ACC514244C51D297F35E5AEA328B8641B33D54DC7C50D2466F9DDDCE98A75F276D48D614B6C4FA675C2017824BED7CC27B46FCBE5B82CE4B433E34AAED2EBEE3182020630820202020101305D3053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A5020504220435302060142FD5CF927300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
        sod = ef.SOD.load(tv_sod)

    with pytest.raises(ef.sod.SODError, match=r'Invalid SignedData version: v1'):
        # Test exception is raised if SignedData object version is 1
        tv_sod = bytes.fromhex('7782078A3082078606092A864886F70D010702A082077730820773020101310F300D060960864801650304020105003081E90606678108010101A081DE0481DB3081D8020100300D060960864801650304020105003081C3302502010104204170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B630250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA08204653082046130820295A00302010202060142FD5CF927304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A50205042204353301E170D3133313231363231343331385A170D3134313231313231343331385A3054310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731183016060355040B0C0F446F63756D656E74205369676E65723112301006035504030C09484A5020504220445330820122300D06092A864886F70D01010105000382010F003082010A02820101009E7CBB065377041232915A044DD3ADC2199AD4C14BC8E58C24A899DBD62A984EEAE2A0006C1D53439246A67A9964D759BC7B9426CE6C4C078363306CF66645F12F39D950FE2C04100E6FF53C310B52F74CD1ED89931496F376D384AB604A570129445F015FCC3595E161B7C591CB5206BC16477D8CDEC09480DBF6262696F62970DA0978807DBA330EE777BF54D471AE1EB257090F1379E198A2D1503344847347BE46764FA00C4E93BACD32143B2E04C6C369CECE7943FD414521849533F9CDB985E42767F1DD792E7EFED3651E3C75DF868FA2101DF45CD5D3D955B23A88DD30A752F4FB9F4E84B518E0CA0F8F2BACE65D61F98115A0EA88DD3A3416017CA30203010001A3523050301F0603551D230418301680141E4D57560C12902366A8FDE11408A37F70EB7D65301D0603551D0E04160414831C30BE878FDF57273010E5B38950E576F7B08A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012003820181002984DC43028839BB24786A4C9C9C37E76368FF6264707970E5B00F7934840904ED90E34B018D5D634D7536E49AFE7B0E872F5D093E6D11BF31C910686A9106F9F773F59C57AEFF983DE6335B5CB403E0FF7D3055F09948878F8BE1BC184F2A03C82C14097FC19DEDDCCF61A2EAE6F8BF1A64BE4C0253CE0BC35AD41E10D6FF08C1EE872349E8D02A722F48144CAB665D0FADF9DB3B36BFB2B15AE4A3B13DC4CF64133B599CDB3AF8A365AC6228096899FEA8D56A24F90DA72B3E95B97FD82C4B8EF9CBB499C3D9F09053A5FDDD51E94A13A004530D74F7DD1B0C88163F9BFA098923DC81D247D75E33CAC3C7E27AEAC627B99AB18E6B03D38260E2DCCFA1D638D17614773BC13EBA0D53E2E3E9A202E0742C25DF471072CDA2A88BA2B25648970BC31132DE84F702ABBC98740B4FEE7C66CD149755A763B801DCF9DC1B52191A3ACC514244C51D297F35E5AEA328B8641B33D54DC7C50D2466F9DDDCE98A75F276D48D614B6C4FA675C2017824BED7CC27B46FCBE5B82CE4B433E34AAED2EBEE3182020630820202020101305D3053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A5020504220435302060142FD5CF927300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
        sod = ef.SOD.load(tv_sod)

    with pytest.raises(ef.sod.SODError, match=r'Invalid SignedData version: v2'):
        # Test exception is raised if SignedData object version is 1
        tv_sod = bytes.fromhex('7782078A3082078606092A864886F70D010702A082077730820773020102310F300D060960864801650304020105003081E90606678108010101A081DE0481DB3081D8020100300D060960864801650304020105003081C3302502010104204170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B630250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA08204653082046130820295A00302010202060142FD5CF927304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A50205042204353301E170D3133313231363231343331385A170D3134313231313231343331385A3054310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731183016060355040B0C0F446F63756D656E74205369676E65723112301006035504030C09484A5020504220445330820122300D06092A864886F70D01010105000382010F003082010A02820101009E7CBB065377041232915A044DD3ADC2199AD4C14BC8E58C24A899DBD62A984EEAE2A0006C1D53439246A67A9964D759BC7B9426CE6C4C078363306CF66645F12F39D950FE2C04100E6FF53C310B52F74CD1ED89931496F376D384AB604A570129445F015FCC3595E161B7C591CB5206BC16477D8CDEC09480DBF6262696F62970DA0978807DBA330EE777BF54D471AE1EB257090F1379E198A2D1503344847347BE46764FA00C4E93BACD32143B2E04C6C369CECE7943FD414521849533F9CDB985E42767F1DD792E7EFED3651E3C75DF868FA2101DF45CD5D3D955B23A88DD30A752F4FB9F4E84B518E0CA0F8F2BACE65D61F98115A0EA88DD3A3416017CA30203010001A3523050301F0603551D230418301680141E4D57560C12902366A8FDE11408A37F70EB7D65301D0603551D0E04160414831C30BE878FDF57273010E5B38950E576F7B08A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012003820181002984DC43028839BB24786A4C9C9C37E76368FF6264707970E5B00F7934840904ED90E34B018D5D634D7536E49AFE7B0E872F5D093E6D11BF31C910686A9106F9F773F59C57AEFF983DE6335B5CB403E0FF7D3055F09948878F8BE1BC184F2A03C82C14097FC19DEDDCCF61A2EAE6F8BF1A64BE4C0253CE0BC35AD41E10D6FF08C1EE872349E8D02A722F48144CAB665D0FADF9DB3B36BFB2B15AE4A3B13DC4CF64133B599CDB3AF8A365AC6228096899FEA8D56A24F90DA72B3E95B97FD82C4B8EF9CBB499C3D9F09053A5FDDD51E94A13A004530D74F7DD1B0C88163F9BFA098923DC81D247D75E33CAC3C7E27AEAC627B99AB18E6B03D38260E2DCCFA1D638D17614773BC13EBA0D53E2E3E9A202E0742C25DF471072CDA2A88BA2B25648970BC31132DE84F702ABBC98740B4FEE7C66CD149755A763B801DCF9DC1B52191A3ACC514244C51D297F35E5AEA328B8641B33D54DC7C50D2466F9DDDCE98A75F276D48D614B6C4FA675C2017824BED7CC27B46FCBE5B82CE4B433E34AAED2EBEE3182020630820202020101305D3053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A5020504220435302060142FD5CF927300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
        sod = ef.SOD.load(tv_sod)

    with pytest.raises(ef.sod.SODError, match=r'Invalid SignedData version: v4'):
        # Test exception is raised if SignedData object version is 1
        tv_sod = bytes.fromhex('7782078A3082078606092A864886F70D010702A082077730820773020104310F300D060960864801650304020105003081E90606678108010101A081DE0481DB3081D8020100300D060960864801650304020105003081C3302502010104204170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B630250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA08204653082046130820295A00302010202060142FD5CF927304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A50205042204353301E170D3133313231363231343331385A170D3134313231313231343331385A3054310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731183016060355040B0C0F446F63756D656E74205369676E65723112301006035504030C09484A5020504220445330820122300D06092A864886F70D01010105000382010F003082010A02820101009E7CBB065377041232915A044DD3ADC2199AD4C14BC8E58C24A899DBD62A984EEAE2A0006C1D53439246A67A9964D759BC7B9426CE6C4C078363306CF66645F12F39D950FE2C04100E6FF53C310B52F74CD1ED89931496F376D384AB604A570129445F015FCC3595E161B7C591CB5206BC16477D8CDEC09480DBF6262696F62970DA0978807DBA330EE777BF54D471AE1EB257090F1379E198A2D1503344847347BE46764FA00C4E93BACD32143B2E04C6C369CECE7943FD414521849533F9CDB985E42767F1DD792E7EFED3651E3C75DF868FA2101DF45CD5D3D955B23A88DD30A752F4FB9F4E84B518E0CA0F8F2BACE65D61F98115A0EA88DD3A3416017CA30203010001A3523050301F0603551D230418301680141E4D57560C12902366A8FDE11408A37F70EB7D65301D0603551D0E04160414831C30BE878FDF57273010E5B38950E576F7B08A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012003820181002984DC43028839BB24786A4C9C9C37E76368FF6264707970E5B00F7934840904ED90E34B018D5D634D7536E49AFE7B0E872F5D093E6D11BF31C910686A9106F9F773F59C57AEFF983DE6335B5CB403E0FF7D3055F09948878F8BE1BC184F2A03C82C14097FC19DEDDCCF61A2EAE6F8BF1A64BE4C0253CE0BC35AD41E10D6FF08C1EE872349E8D02A722F48144CAB665D0FADF9DB3B36BFB2B15AE4A3B13DC4CF64133B599CDB3AF8A365AC6228096899FEA8D56A24F90DA72B3E95B97FD82C4B8EF9CBB499C3D9F09053A5FDDD51E94A13A004530D74F7DD1B0C88163F9BFA098923DC81D247D75E33CAC3C7E27AEAC627B99AB18E6B03D38260E2DCCFA1D638D17614773BC13EBA0D53E2E3E9A202E0742C25DF471072CDA2A88BA2B25648970BC31132DE84F702ABBC98740B4FEE7C66CD149755A763B801DCF9DC1B52191A3ACC514244C51D297F35E5AEA328B8641B33D54DC7C50D2466F9DDDCE98A75F276D48D614B6C4FA675C2017824BED7CC27B46FCBE5B82CE4B433E34AAED2EBEE3182020630820202020101305D3053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A5020504220435302060142FD5CF927300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
        sod = ef.SOD.load(tv_sod)

    with pytest.raises(ef.sod.SODError, match=r'Invalid encapContentInfo type: 1.2.840.113549.1.7.1, expected 2.23.136.1.1.1'):
        # Test strict parsing raises exception when content type for LDS security object is set to 1.2.840.113549.1.7.1 - id-data (otherwise valid for relaxed parsing).
        tv_sod = bytes.fromhex('778207903082078c06092a864886f70d010702a082077d30820779020103310f300d060960864801650304020105003081ec06092a864886f70d010701a081de0481db3081d8020100300d060960864801650304020105003081c3302502010104204170ca879fce6a22ffef1567ff88079f415c66ead250ab5f23781ac2cdbf42b630250201020420a9a1b09dfd598087ab3fce4ae2ec65b1a1525bd258bfc27df4419f8a65e5474530250201030420403e4d17c26ebc832411898161d8fd5d99c58ee865cb3759b529aa782c7ede00302502010e0420cf5004ffccd64e1a8bd3a42fd53814ec3d4481640be1906d0ecfeb016ef6a6ae302502010404204c7a0f0ddaa473123834f1b0713ed9453d1d1d58bce447fb1736d40a0761c17ba08204653082046130820295a00302010202060142fd5cf927304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a2030201203053310b300906035504061302444531173015060355040a0c0e484a5020436f6e73756c74696e6731173015060355040b0c0e436f756e747279205369676e65723112301006035504030c09484a50205042204353301e170d3133313231363231343331385a170d3134313231313231343331385a3054310b300906035504061302444531173015060355040a0c0e484a5020436f6e73756c74696e6731183016060355040b0c0f446f63756d656e74205369676e65723112301006035504030c09484a5020504220445330820122300d06092a864886f70d01010105000382010f003082010a02820101009e7cbb065377041232915a044dd3adc2199ad4c14bc8e58c24a899dbd62a984eeae2a0006c1d53439246a67a9964d759bc7b9426ce6c4c078363306cf66645f12f39d950fe2c04100e6ff53c310b52f74cd1ed89931496f376d384ab604a570129445f015fcc3595e161b7c591cb5206bc16477d8cdec09480dbf6262696f62970da0978807dba330ee777bf54d471ae1eb257090f1379e198a2d1503344847347be46764fa00c4e93bacd32143b2e04c6c369cece7943fd414521849533f9cdb985e42767f1dd792e7efed3651e3c75df868fa2101df45cd5d3d955b23a88dd30a752f4fb9f4e84b518e0ca0f8f2bace65d61f98115a0ea88dd3a3416017ca30203010001a3523050301f0603551d230418301680141e4d57560c12902366a8fde11408a37f70eb7d65301d0603551d0e04160414831c30be878fdf57273010e5b38950e576f7b08a300e0603551d0f0101ff040403020780304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003820181002984dc43028839bb24786a4c9c9c37e76368ff6264707970e5b00f7934840904ed90e34b018d5d634d7536e49afe7b0e872f5d093e6d11bf31c910686a9106f9f773f59c57aeff983de6335b5cb403e0ff7d3055f09948878f8be1bc184f2a03c82c14097fc19deddccf61a2eae6f8bf1a64be4c0253ce0bc35ad41e10d6ff08c1ee872349e8d02a722f48144cab665d0fadf9db3b36bfb2b15ae4a3b13dc4cf64133b599cdb3af8a365ac6228096899fea8d56a24f90da72b3e95b97fd82c4b8ef9cbb499c3d9f09053a5fddd51e94a13a004530d74f7dd1b0c88163f9bfa098923dc81d247d75e33cac3c7e27aeac627b99ab18e6b03d38260e2dccfa1d638d17614773bc13eba0d53e2e3e9a202e0742c25df471072cda2a88ba2b25648970bc31132de84f702abbc98740b4fee7c66cd149755a763b801dcf9dc1b52191a3acc514244c51d297f35e5aea328b8641b33d54dc7c50d2466f9dddce98a75f276d48d614b6c4fa675c2017824bed7cc27b46fcbe5b82ce4b433e34aaed2ebee3182020930820205020101305d3053310b300906035504061302444531173015060355040a0c0e484a5020436f6e73756c74696e6731173015060355040b0c0e436f756e747279205369676e65723112301006035504030c09484a5020504220435302060142fd5cf927300d06096086480165030402010500a04b301806092a864886f70d010903310b06092a864886f70d010701302f06092a864886f70d01090431220420b46a0d05e280f398efeeebff67e78c736add15e75670b1ad4c6c534e8187b9d6304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012004820100761106e9fbd2ed1b2f75027daf13975a4c7adfc54d675d2dd2bba762bc073d9288af4b1b87ba7987d53fa1d321d1943f58573f4913424e2bcdd080c2d8927a985be2bdcaf6b8fe21ec99d8227f052ed118b7eae6029f57889ca723912076916355068ebbcf46f19c3fbb49dcf1e9f3b10df11e270fac11bc6d1e3c5adf68e0e46381a45f737e91ee9f889db6d418aa2c6c3213c47fbc2787f0134384b343cc921a9a03878eba79ba00901115495942c3e7b0e4da09e0916c172228ad28d9dbec915f32e58d7431480443030c2c3d1def840223fed41a92c5b30aa2ce9ed346cbb8bb172a2eff73e0b8cfec89071a07dc62627421f808da541a58a1a572e7583f')
        sod = ef.SOD.load(tv_sod, strict = True)

    with pytest.raises(ef.sod.SODError, match=r'Invalid encapContentInfo type: 1.2.840.113549.1.7.5, expected 2.23.136.1.1.1'):
        # Test relaxed parsing raises exception when invalid content type for LDS security object is set to 1.2.840.113549.1.7.5.
        tv_sod = bytes.fromhex('778207903082078c06092a864886f70d010702a082077d30820779020103310f300d060960864801650304020105003081ec06092a864886f70d010705a081de0481db3081d8020100300d060960864801650304020105003081c3302502010104204170ca879fce6a22ffef1567ff88079f415c66ead250ab5f23781ac2cdbf42b630250201020420a9a1b09dfd598087ab3fce4ae2ec65b1a1525bd258bfc27df4419f8a65e5474530250201030420403e4d17c26ebc832411898161d8fd5d99c58ee865cb3759b529aa782c7ede00302502010e0420cf5004ffccd64e1a8bd3a42fd53814ec3d4481640be1906d0ecfeb016ef6a6ae302502010404204c7a0f0ddaa473123834f1b0713ed9453d1d1d58bce447fb1736d40a0761c17ba08204653082046130820295a00302010202060142fd5cf927304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a2030201203053310b300906035504061302444531173015060355040a0c0e484a5020436f6e73756c74696e6731173015060355040b0c0e436f756e747279205369676e65723112301006035504030c09484a50205042204353301e170d3133313231363231343331385a170d3134313231313231343331385a3054310b300906035504061302444531173015060355040a0c0e484a5020436f6e73756c74696e6731183016060355040b0c0f446f63756d656e74205369676e65723112301006035504030c09484a5020504220445330820122300d06092a864886f70d01010105000382010f003082010a02820101009e7cbb065377041232915a044dd3adc2199ad4c14bc8e58c24a899dbd62a984eeae2a0006c1d53439246a67a9964d759bc7b9426ce6c4c078363306cf66645f12f39d950fe2c04100e6ff53c310b52f74cd1ed89931496f376d384ab604a570129445f015fcc3595e161b7c591cb5206bc16477d8cdec09480dbf6262696f62970da0978807dba330ee777bf54d471ae1eb257090f1379e198a2d1503344847347be46764fa00c4e93bacd32143b2e04c6c369cece7943fd414521849533f9cdb985e42767f1dd792e7efed3651e3c75df868fa2101df45cd5d3d955b23a88dd30a752f4fb9f4e84b518e0ca0f8f2bace65d61f98115a0ea88dd3a3416017ca30203010001a3523050301f0603551d230418301680141e4d57560c12902366a8fde11408a37f70eb7d65301d0603551d0e04160414831c30be878fdf57273010e5b38950e576f7b08a300e0603551d0f0101ff040403020780304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003820181002984dc43028839bb24786a4c9c9c37e76368ff6264707970e5b00f7934840904ed90e34b018d5d634d7536e49afe7b0e872f5d093e6d11bf31c910686a9106f9f773f59c57aeff983de6335b5cb403e0ff7d3055f09948878f8be1bc184f2a03c82c14097fc19deddccf61a2eae6f8bf1a64be4c0253ce0bc35ad41e10d6ff08c1ee872349e8d02a722f48144cab665d0fadf9db3b36bfb2b15ae4a3b13dc4cf64133b599cdb3af8a365ac6228096899fea8d56a24f90da72b3e95b97fd82c4b8ef9cbb499c3d9f09053a5fddd51e94a13a004530d74f7dd1b0c88163f9bfa098923dc81d247d75e33cac3c7e27aeac627b99ab18e6b03d38260e2dccfa1d638d17614773bc13eba0d53e2e3e9a202e0742c25df471072cda2a88ba2b25648970bc31132de84f702abbc98740b4fee7c66cd149755a763b801dcf9dc1b52191a3acc514244c51d297f35e5aea328b8641b33d54dc7c50d2466f9dddce98a75f276d48d614b6c4fa675c2017824bed7cc27b46fcbe5b82ce4b433e34aaed2ebee3182020930820205020101305d3053310b300906035504061302444531173015060355040a0c0e484a5020436f6e73756c74696e6731173015060355040b0c0e436f756e747279205369676e65723112301006035504030c09484a5020504220435302060142fd5cf927300d06096086480165030402010500a04b301806092a864886f70d010903310b06092a864886f70d010701302f06092a864886f70d01090431220420b46a0d05e280f398efeeebff67e78c736add15e75670b1ad4c6c534e8187b9d6304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012004820100761106e9fbd2ed1b2f75027daf13975a4c7adfc54d675d2dd2bba762bc073d9288af4b1b87ba7987d53fa1d321d1943f58573f4913424e2bcdd080c2d8927a985be2bdcaf6b8fe21ec99d8227f052ed118b7eae6029f57889ca723912076916355068ebbcf46f19c3fbb49dcf1e9f3b10df11e270fac11bc6d1e3c5adf68e0e46381a45f737e91ee9f889db6d418aa2c6c3213c47fbc2787f0134384b343cc921a9a03878eba79ba00901115495942c3e7b0e4da09e0916c172228ad28d9dbec915f32e58d7431480443030c2c3d1def840223fed41a92c5b30aa2ce9ed346cbb8bb172a2eff73e0b8cfec89071a07dc62627421f808da541a58a1a572e7583f')
        sod = ef.SOD.load(tv_sod, strict = False)

    with pytest.raises(ef.sod.SODError, match=r'Invalid encapContentInfo type: 1.2.840.113549.1.7.5, expected 2.23.136.1.1.1'):
        # Test strict parsing raises exception when invalid content type for LDS security object is set to 1.2.840.113549.1.7.5.
        tv_sod = bytes.fromhex('778207903082078c06092a864886f70d010702a082077d30820779020103310f300d060960864801650304020105003081ec06092a864886f70d010705a081de0481db3081d8020100300d060960864801650304020105003081c3302502010104204170ca879fce6a22ffef1567ff88079f415c66ead250ab5f23781ac2cdbf42b630250201020420a9a1b09dfd598087ab3fce4ae2ec65b1a1525bd258bfc27df4419f8a65e5474530250201030420403e4d17c26ebc832411898161d8fd5d99c58ee865cb3759b529aa782c7ede00302502010e0420cf5004ffccd64e1a8bd3a42fd53814ec3d4481640be1906d0ecfeb016ef6a6ae302502010404204c7a0f0ddaa473123834f1b0713ed9453d1d1d58bce447fb1736d40a0761c17ba08204653082046130820295a00302010202060142fd5cf927304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a2030201203053310b300906035504061302444531173015060355040a0c0e484a5020436f6e73756c74696e6731173015060355040b0c0e436f756e747279205369676e65723112301006035504030c09484a50205042204353301e170d3133313231363231343331385a170d3134313231313231343331385a3054310b300906035504061302444531173015060355040a0c0e484a5020436f6e73756c74696e6731183016060355040b0c0f446f63756d656e74205369676e65723112301006035504030c09484a5020504220445330820122300d06092a864886f70d01010105000382010f003082010a02820101009e7cbb065377041232915a044dd3adc2199ad4c14bc8e58c24a899dbd62a984eeae2a0006c1d53439246a67a9964d759bc7b9426ce6c4c078363306cf66645f12f39d950fe2c04100e6ff53c310b52f74cd1ed89931496f376d384ab604a570129445f015fcc3595e161b7c591cb5206bc16477d8cdec09480dbf6262696f62970da0978807dba330ee777bf54d471ae1eb257090f1379e198a2d1503344847347be46764fa00c4e93bacd32143b2e04c6c369cece7943fd414521849533f9cdb985e42767f1dd792e7efed3651e3c75df868fa2101df45cd5d3d955b23a88dd30a752f4fb9f4e84b518e0ca0f8f2bace65d61f98115a0ea88dd3a3416017ca30203010001a3523050301f0603551d230418301680141e4d57560c12902366a8fde11408a37f70eb7d65301d0603551d0e04160414831c30be878fdf57273010e5b38950e576f7b08a300e0603551d0f0101ff040403020780304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003820181002984dc43028839bb24786a4c9c9c37e76368ff6264707970e5b00f7934840904ed90e34b018d5d634d7536e49afe7b0e872f5d093e6d11bf31c910686a9106f9f773f59c57aeff983de6335b5cb403e0ff7d3055f09948878f8be1bc184f2a03c82c14097fc19deddccf61a2eae6f8bf1a64be4c0253ce0bc35ad41e10d6ff08c1ee872349e8d02a722f48144cab665d0fadf9db3b36bfb2b15ae4a3b13dc4cf64133b599cdb3af8a365ac6228096899fea8d56a24f90da72b3e95b97fd82c4b8ef9cbb499c3d9f09053a5fddd51e94a13a004530d74f7dd1b0c88163f9bfa098923dc81d247d75e33cac3c7e27aeac627b99ab18e6b03d38260e2dccfa1d638d17614773bc13eba0d53e2e3e9a202e0742c25df471072cda2a88ba2b25648970bc31132de84f702abbc98740b4fee7c66cd149755a763b801dcf9dc1b52191a3acc514244c51d297f35e5aea328b8641b33d54dc7c50d2466f9dddce98a75f276d48d614b6c4fa675c2017824bed7cc27b46fcbe5b82ce4b433e34aaed2ebee3182020930820205020101305d3053310b300906035504061302444531173015060355040a0c0e484a5020436f6e73756c74696e6731173015060355040b0c0e436f756e747279205369676e65723112301006035504030c09484a5020504220435302060142fd5cf927300d06096086480165030402010500a04b301806092a864886f70d010903310b06092a864886f70d010701302f06092a864886f70d01090431220420b46a0d05e280f398efeeebff67e78c736add15e75670b1ad4c6c534e8187b9d6304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012004820100761106e9fbd2ed1b2f75027daf13975a4c7adfc54d675d2dd2bba762bc073d9288af4b1b87ba7987d53fa1d321d1943f58573f4913424e2bcdd080c2d8927a985be2bdcaf6b8fe21ec99d8227f052ed118b7eae6029f57889ca723912076916355068ebbcf46f19c3fbb49dcf1e9f3b10df11e270fac11bc6d1e3c5adf68e0e46381a45f737e91ee9f889db6d418aa2c6c3213c47fbc2787f0134384b343cc921a9a03878eba79ba00901115495942c3e7b0e4da09e0916c172228ad28d9dbec915f32e58d7431480443030c2c3d1def840223fed41a92c5b30aa2ce9ed346cbb8bb172a2eff73e0b8cfec89071a07dc62627421f808da541a58a1a572e7583f')
        sod = ef.SOD.load(tv_sod, strict = True)

    with pytest.raises(ef.sod.SODError, match=r'Unsupported LDSSecurityObject version: 2, expected 0 or 1'):
        # Test parsing raises exception when parsed LDSSecurityObject is version 2
        tv_sod = bytes.fromhex('7782078A3082078606092A864886F70D010702A082077730820773020103310F300D060960864801650304020105003081E90606678108010101A081DE0481DB3081D8020102300D060960864801650304020105003081C3302502010104204170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B630250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA08204653082046130820295A00302010202060142FD5CF927304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A50205042204353301E170D3133313231363231343331385A170D3134313231313231343331385A3054310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731183016060355040B0C0F446F63756D656E74205369676E65723112301006035504030C09484A5020504220445330820122300D06092A864886F70D01010105000382010F003082010A02820101009E7CBB065377041232915A044DD3ADC2199AD4C14BC8E58C24A899DBD62A984EEAE2A0006C1D53439246A67A9964D759BC7B9426CE6C4C078363306CF66645F12F39D950FE2C04100E6FF53C310B52F74CD1ED89931496F376D384AB604A570129445F015FCC3595E161B7C591CB5206BC16477D8CDEC09480DBF6262696F62970DA0978807DBA330EE777BF54D471AE1EB257090F1379E198A2D1503344847347BE46764FA00C4E93BACD32143B2E04C6C369CECE7943FD414521849533F9CDB985E42767F1DD792E7EFED3651E3C75DF868FA2101DF45CD5D3D955B23A88DD30A752F4FB9F4E84B518E0CA0F8F2BACE65D61F98115A0EA88DD3A3416017CA30203010001A3523050301F0603551D230418301680141E4D57560C12902366A8FDE11408A37F70EB7D65301D0603551D0E04160414831C30BE878FDF57273010E5B38950E576F7B08A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012003820181002984DC43028839BB24786A4C9C9C37E76368FF6264707970E5B00F7934840904ED90E34B018D5D634D7536E49AFE7B0E872F5D093E6D11BF31C910686A9106F9F773F59C57AEFF983DE6335B5CB403E0FF7D3055F09948878F8BE1BC184F2A03C82C14097FC19DEDDCCF61A2EAE6F8BF1A64BE4C0253CE0BC35AD41E10D6FF08C1EE872349E8D02A722F48144CAB665D0FADF9DB3B36BFB2B15AE4A3B13DC4CF64133B599CDB3AF8A365AC6228096899FEA8D56A24F90DA72B3E95B97FD82C4B8EF9CBB499C3D9F09053A5FDDD51E94A13A004530D74F7DD1B0C88163F9BFA098923DC81D247D75E33CAC3C7E27AEAC627B99AB18E6B03D38260E2DCCFA1D638D17614773BC13EBA0D53E2E3E9A202E0742C25DF471072CDA2A88BA2B25648970BC31132DE84F702ABBC98740B4FEE7C66CD149755A763B801DCF9DC1B52191A3ACC514244C51D297F35E5AEA328B8641B33D54DC7C50D2466F9DDDCE98A75F276D48D614B6C4FA675C2017824BED7CC27B46FCBE5B82CE4B433E34AAED2EBEE3182020630820202020101305D3053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A5020504220435302060142FD5CF927300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
        sod = ef.SOD.load(tv_sod)

    with pytest.raises(ef.sod.SODError, match=r'Unsupported LDSSecurityObject version: -1, expected 0 or 1'):
        # Test parsing raises exception when parsed LDSSecurityObject is version 2
        tv_sod = bytes.fromhex('7782078A3082078606092A864886F70D010702A082077730820773020103310F300D060960864801650304020105003081E90606678108010101A081DE0481DB3081D80201FF300D060960864801650304020105003081C3302502010104204170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B630250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA08204653082046130820295A00302010202060142FD5CF927304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A50205042204353301E170D3133313231363231343331385A170D3134313231313231343331385A3054310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731183016060355040B0C0F446F63756D656E74205369676E65723112301006035504030C09484A5020504220445330820122300D06092A864886F70D01010105000382010F003082010A02820101009E7CBB065377041232915A044DD3ADC2199AD4C14BC8E58C24A899DBD62A984EEAE2A0006C1D53439246A67A9964D759BC7B9426CE6C4C078363306CF66645F12F39D950FE2C04100E6FF53C310B52F74CD1ED89931496F376D384AB604A570129445F015FCC3595E161B7C591CB5206BC16477D8CDEC09480DBF6262696F62970DA0978807DBA330EE777BF54D471AE1EB257090F1379E198A2D1503344847347BE46764FA00C4E93BACD32143B2E04C6C369CECE7943FD414521849533F9CDB985E42767F1DD792E7EFED3651E3C75DF868FA2101DF45CD5D3D955B23A88DD30A752F4FB9F4E84B518E0CA0F8F2BACE65D61F98115A0EA88DD3A3416017CA30203010001A3523050301F0603551D230418301680141E4D57560C12902366A8FDE11408A37F70EB7D65301D0603551D0E04160414831C30BE878FDF57273010E5B38950E576F7B08A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012003820181002984DC43028839BB24786A4C9C9C37E76368FF6264707970E5B00F7934840904ED90E34B018D5D634D7536E49AFE7B0E872F5D093E6D11BF31C910686A9106F9F773F59C57AEFF983DE6335B5CB403E0FF7D3055F09948878F8BE1BC184F2A03C82C14097FC19DEDDCCF61A2EAE6F8BF1A64BE4C0253CE0BC35AD41E10D6FF08C1EE872349E8D02A722F48144CAB665D0FADF9DB3B36BFB2B15AE4A3B13DC4CF64133B599CDB3AF8A365AC6228096899FEA8D56A24F90DA72B3E95B97FD82C4B8EF9CBB499C3D9F09053A5FDDD51E94A13A004530D74F7DD1B0C88163F9BFA098923DC81D247D75E33CAC3C7E27AEAC627B99AB18E6B03D38260E2DCCFA1D638D17614773BC13EBA0D53E2E3E9A202E0742C25DF471072CDA2A88BA2B25648970BC31132DE84F702ABBC98740B4FEE7C66CD149755A763B801DCF9DC1B52191A3ACC514244C51D297F35E5AEA328B8641B33D54DC7C50D2466F9DDDCE98A75F276D48D614B6C4FA675C2017824BED7CC27B46FCBE5B82CE4B433E34AAED2EBEE3182020630820202020101305D3053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A5020504220435302060142FD5CF927300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
        sod = ef.SOD.load(tv_sod)

    with pytest.raises(ef.sod.SODError, match=r'Extra data - 1 bytes of trailing data were provided'):
        # Test strict parsing raises exception when there is trailing data
        tv_sod = bytes.fromhex('7782078A3082078606092A864886F70D010702A082077730820773020103310F300D060960864801650304020105003081E90606678108010101A081DE0481DB3081D8020100300D060960864801650304020105003081C3302502010104204170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B630250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA08204653082046130820295A00302010202060142FD5CF927304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A50205042204353301E170D3133313231363231343331385A170D3134313231313231343331385A3054310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731183016060355040B0C0F446F63756D656E74205369676E65723112301006035504030C09484A5020504220445330820122300D06092A864886F70D01010105000382010F003082010A02820101009E7CBB065377041232915A044DD3ADC2199AD4C14BC8E58C24A899DBD62A984EEAE2A0006C1D53439246A67A9964D759BC7B9426CE6C4C078363306CF66645F12F39D950FE2C04100E6FF53C310B52F74CD1ED89931496F376D384AB604A570129445F015FCC3595E161B7C591CB5206BC16477D8CDEC09480DBF6262696F62970DA0978807DBA330EE777BF54D471AE1EB257090F1379E198A2D1503344847347BE46764FA00C4E93BACD32143B2E04C6C369CECE7943FD414521849533F9CDB985E42767F1DD792E7EFED3651E3C75DF868FA2101DF45CD5D3D955B23A88DD30A752F4FB9F4E84B518E0CA0F8F2BACE65D61F98115A0EA88DD3A3416017CA30203010001A3523050301F0603551D230418301680141E4D57560C12902366A8FDE11408A37F70EB7D65301D0603551D0E04160414831C30BE878FDF57273010E5B38950E576F7B08A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012003820181002984DC43028839BB24786A4C9C9C37E76368FF6264707970E5B00F7934840904ED90E34B018D5D634D7536E49AFE7B0E872F5D093E6D11BF31C910686A9106F9F773F59C57AEFF983DE6335B5CB403E0FF7D3055F09948878F8BE1BC184F2A03C82C14097FC19DEDDCCF61A2EAE6F8BF1A64BE4C0253CE0BC35AD41E10D6FF08C1EE872349E8D02A722F48144CAB665D0FADF9DB3B36BFB2B15AE4A3B13DC4CF64133B599CDB3AF8A365AC6228096899FEA8D56A24F90DA72B3E95B97FD82C4B8EF9CBB499C3D9F09053A5FDDD51E94A13A004530D74F7DD1B0C88163F9BFA098923DC81D247D75E33CAC3C7E27AEAC627B99AB18E6B03D38260E2DCCFA1D638D17614773BC13EBA0D53E2E3E9A202E0742C25DF471072CDA2A88BA2B25648970BC31132DE84F702ABBC98740B4FEE7C66CD149755A763B801DCF9DC1B52191A3ACC514244C51D297F35E5AEA328B8641B33D54DC7C50D2466F9DDDCE98A75F276D48D614B6C4FA675C2017824BED7CC27B46FCBE5B82CE4B433E34AAED2EBEE3182020630820202020101305D3053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A5020504220435302060142FD5CF927300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F00')
        sod = ef.SOD.load(tv_sod, strict = True)

    with pytest.raises(ef.sod.SODError, match="Content digest doesn't match signed digest"):
        # Test vector taken from https://www.etsi.org/
        # https://www.etsi.org/deliver/etsi_tr/103200_103299/103200/01.01.01_60/tr_103200v010101p.pdf
        # https://docbox.etsi.org/MTS/MTS/05-CONTRIBUTIONS/2011/MTS(11)0044_DMIMTS-00127_ePassport_Prototype_Platform.zip
        # ePassport_Data/CFG/DFLT/EACAA/EF_SOD.bin
        #
        # Modified hash value of DG1 to ...F6
        tv_sod = bytes.fromhex('778207903082078C06092A864886F70D010702A082077D30820779020103310F300D06096086480165030402010500308201120606678108010101A0820106048201023081FF020100300D060960864801650304020105003081EA3025020101042051B6FC0EF1946F3A86D2A4C9557C5D8ECFF13113B4131089C5C48BF7291FFDF630250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420A1A7B2285B954DD053253C1D851709F6380731176CC9EB1123546439C704108A302502010F04205265ECB286F406D93EC5B8965659D45450D8DA1A97575DEF4EFC7303C7408730302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA082044D308204493082027DA00302010202060130846F2B3E304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203047310B3009060355040613024445310D300B060355040A0C044554534931173015060355040B0C0E436F756E747279205369676E65723110300E06035504030C0745545349204353301E170D3131303631323135313835365A170D3132303630363135313835365A3048310B3009060355040613024445310D300B060355040A0C044554534931183016060355040B0C0F446F63756D656E74205369676E65723110300E06035504030C074554534920445330820122300D06092A864886F70D01010105000382010F003082010A0282010100D986CFA346CDE37F6F900ADDAE5D91CA955FF02AAB8AD8BBF4EF6D2A7BD25EB67F6EA56F2C4F2BEA026E66569C9E242607B19ECC84F8E441CE973D8BD76F7C4D2897E1D8CBF937C29272EF68FB33E46CBF02969CACD84A778F6FDBEE5C0C06E5FF5BAEF3BB0EF2FC2B66CCF768F0970E9A5D93D5B506C31B41BF6AFB0A3840DF287EE3BEE348FA05D47F855486851A6D966E2DC002EF028FA2491BA25783C74D5CE839B2C6F6A43A84502353C0C0C08F027A4AD1FB5431FC11D097EF228B5721D02C264A7F961A8C441F266BC755FF36C3E442DD674909FFD21129623707AFC0F1F701BF1C586CB6FDF5321F50ACDE6241E4684FEAB8D7958843656358AB3D510203010001A3523050301F0603551D23041830168014CEA56178E7A1585B3AEF1E25EF9EC82940158D10301D0603551D0E04160414731FE7AEC52D7A75624F8DC4D794CEA4709EFB5A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201200382018100B15A5DB7E7280F1A15070817E6E877079741910A33C7C99F783CB61003A45120B6348545FD588C676D96BBE9AF609BDEE9D633A1C1B5C302F4B24C299C5B27DA68A84756569186EC9C417F40B19BC6F9639FC0B7DEFA77526DABBCE014D9C3578718373CB4289D0365F2B78B52EB274198F4820C33EC0496EBFB16960D17A49EBA1859E4A0737EF6C91AA776B712DB2DF9A44933FC5AFA96E532ABF896C1C1CD0076A6AF0746FEDC212C8F41B257F45626C064EACD3FC244232C0689768F0A30C0FA4D46422736AA26C1FA6D880623EB86C04920312D72B044985AC03A0A6EA3F4EFF784C7FD62BB751D240E7A939DBFFAAE999FCB237643B3A032078D2471F78C38487A6860E0C1CD23B796E12484C32B737E13A0F44E3BAF632204440150F035C09B1827BF87692C766E93AFEC3616B984916BC43006EFA5BB92ACD25344095D276FB615E38D0311BB3B849FD0E5269B8B0A85E7FC649A4B5C2BFE05A3D22B3EEBA432F34D0883A6AED5E119CB030396714D19E4D93E006EDFF3DD6E177C40318201FA308201F602010130513047310B3009060355040613024445310D300B060355040A0C044554534931173015060355040B0C0E436F756E747279205369676E65723110300E06035504030C074554534920435302060130846F2B3E300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B07B3583840A50F05E0B0AC5C8310629314B377D2F843FC82110A3B072BE5227304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100599622056634871C86D5161CCA6AF851F14148E0E7EB79B1186DD6BEDF5BD0343EDB6C49B664E9FB459E742CA83358CE83E6B225A0CBFA7C3E9C6AF6D5BC2F4040DD47BF24CACB06FBDD933EEFAD360542656E1F65E0010B8EAE4DA084FC7B78ECB0CED647580BD1E8E2F8660252721E6DC8BD83A8EBE27F780FDBCBEA49D24C6A8A596BA4F4673A04409F2C1EA1CBC6802C9748DD5B2DF042391BA87650447C7E3BAD05553ACDEB96972E3907F425571D767F82219E02BB8839E7FEC9CFE07DCB88B5831A511383DADF5C7C0CB1CE1BD6C2B8B02C2C20DB27402DD3B0CE171993C417D065DD9A0B278E641CF51BABBCCA1128A400ED4AB7C0FD531E4D1E475C')
        sod = ef.SOD.load(tv_sod)
        tv_dg1 = ef.DG1.load(bytes.fromhex('615B5F1F58503C443C3C4D55535445524D414E4E3C3C4552494B413C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C433131543030324A4D34443C3C3936303831323246313331303331373C3C3C3C3C3C3C3C3C3C3C3C3C3C3C36'))
        assert sod.ldsSecurityObject.contains(tv_dg1) == False
        sod.verify(sod.signers[0], sod.getDscCertificate(sod.signers[0]))

    with pytest.raises(ef.sod.SODError, match="Signature verification failed"):
        # Test vector taken from https://www.etsi.org/
        # https://www.etsi.org/deliver/etsi_tr/103200_103299/103200/01.01.01_60/tr_103200v010101p.pdf
        # https://docbox.etsi.org/MTS/MTS/05-CONTRIBUTIONS/2011/MTS(11)0044_DMIMTS-00127_ePassport_Prototype_Platform.zip
        # ePassport_Data/CFG/DFLT/EACAA/EF_SOD.bin
        #
        # Modified last byte in signature of SignerInfo from 0x5C to 0x5D
        tv_sod = bytes.fromhex('778207903082078C06092A864886F70D010702A082077D30820779020103310F300D06096086480165030402010500308201120606678108010101A0820106048201023081FF020100300D060960864801650304020105003081EA3025020101042051B6FC0EF1946F3A86D2A4C9557C5D8ECFF13113B4131089C5C48BF7291FFDF530250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420A1A7B2285B954DD053253C1D851709F6380731176CC9EB1123546439C704108A302502010F04205265ECB286F406D93EC5B8965659D45450D8DA1A97575DEF4EFC7303C7408730302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA082044D308204493082027DA00302010202060130846F2B3E304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203047310B3009060355040613024445310D300B060355040A0C044554534931173015060355040B0C0E436F756E747279205369676E65723110300E06035504030C0745545349204353301E170D3131303631323135313835365A170D3132303630363135313835365A3048310B3009060355040613024445310D300B060355040A0C044554534931183016060355040B0C0F446F63756D656E74205369676E65723110300E06035504030C074554534920445330820122300D06092A864886F70D01010105000382010F003082010A0282010100D986CFA346CDE37F6F900ADDAE5D91CA955FF02AAB8AD8BBF4EF6D2A7BD25EB67F6EA56F2C4F2BEA026E66569C9E242607B19ECC84F8E441CE973D8BD76F7C4D2897E1D8CBF937C29272EF68FB33E46CBF02969CACD84A778F6FDBEE5C0C06E5FF5BAEF3BB0EF2FC2B66CCF768F0970E9A5D93D5B506C31B41BF6AFB0A3840DF287EE3BEE348FA05D47F855486851A6D966E2DC002EF028FA2491BA25783C74D5CE839B2C6F6A43A84502353C0C0C08F027A4AD1FB5431FC11D097EF228B5721D02C264A7F961A8C441F266BC755FF36C3E442DD674909FFD21129623707AFC0F1F701BF1C586CB6FDF5321F50ACDE6241E4684FEAB8D7958843656358AB3D510203010001A3523050301F0603551D23041830168014CEA56178E7A1585B3AEF1E25EF9EC82940158D10301D0603551D0E04160414731FE7AEC52D7A75624F8DC4D794CEA4709EFB5A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201200382018100B15A5DB7E7280F1A15070817E6E877079741910A33C7C99F783CB61003A45120B6348545FD588C676D96BBE9AF609BDEE9D633A1C1B5C302F4B24C299C5B27DA68A84756569186EC9C417F40B19BC6F9639FC0B7DEFA77526DABBCE014D9C3578718373CB4289D0365F2B78B52EB274198F4820C33EC0496EBFB16960D17A49EBA1859E4A0737EF6C91AA776B712DB2DF9A44933FC5AFA96E532ABF896C1C1CD0076A6AF0746FEDC212C8F41B257F45626C064EACD3FC244232C0689768F0A30C0FA4D46422736AA26C1FA6D880623EB86C04920312D72B044985AC03A0A6EA3F4EFF784C7FD62BB751D240E7A939DBFFAAE999FCB237643B3A032078D2471F78C38487A6860E0C1CD23B796E12484C32B737E13A0F44E3BAF632204440150F035C09B1827BF87692C766E93AFEC3616B984916BC43006EFA5BB92ACD25344095D276FB615E38D0311BB3B849FD0E5269B8B0A85E7FC649A4B5C2BFE05A3D22B3EEBA432F34D0883A6AED5E119CB030396714D19E4D93E006EDFF3DD6E177C40318201FA308201F602010130513047310B3009060355040613024445310D300B060355040A0C044554534931173015060355040B0C0E436F756E747279205369676E65723110300E06035504030C074554534920435302060130846F2B3E300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B07B3583840A50F05E0B0AC5C8310629314B377D2F843FC82110A3B072BE5227304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100599622056634871C86D5161CCA6AF851F14148E0E7EB79B1186DD6BEDF5BD0343EDB6C49B664E9FB459E742CA83358CE83E6B225A0CBFA7C3E9C6AF6D5BC2F4040DD47BF24CACB06FBDD933EEFAD360542656E1F65E0010B8EAE4DA084FC7B78ECB0CED647580BD1E8E2F8660252721E6DC8BD83A8EBE27F780FDBCBEA49D24C6A8A596BA4F4673A04409F2C1EA1CBC6802C9748DD5B2DF042391BA87650447C7E3BAD05553ACDEB96972E3907F425571D767F82219E02BB8839E7FEC9CFE07DCB88B5831A511383DADF5C7C0CB1CE1BD6C2B8B02C2C20DB27402DD3B0CE171993C417D065DD9A0B278E641CF51BABBCCA1128A400ED4AB7C0FD531E4D1E475D')
        sod = ef.SOD.load(tv_sod)
        tv_dg1 = ef.DG1.load(bytes.fromhex('615B5F1F58503C443C3C4D55535445524D414E4E3C3C4552494B413C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C433131543030324A4D34443C3C3936303831323246313331303331373C3C3C3C3C3C3C3C3C3C3C3C3C3C3C36'))
        assert sod.ldsSecurityObject.contains(tv_dg1) == True
        sod.verify(sod.signers[0], sod.getDscCertificate(sod.signers[0]))

    with pytest.raises(ef.sod.SODError, match="Content digest doesn't match signed digest"):
        # Test vector taken from https://www.etsi.org/
        # https://www.etsi.org/deliver/etsi_tr/103200_103299/103200/01.01.01_60/tr_103200v010101p.pdf
        # https://docbox.etsi.org/MTS/MTS/05-CONTRIBUTIONS/2011/MTS(11)0044_DMIMTS-00127_ePassport_Prototype_Platform.zip
        # ePassport_Data/CFG/DFLT/EACAA/EF_SOD.bin
        #
        # Modified hash value of DG14 to ..F7...
        tv_sod = bytes.fromhex('778207903082078C06092A864886F70D010702A082077D30820779020103310F300D06096086480165030402010500308201120606678108010101A0820106048201023081FF020100300D060960864801650304020105003081EA3025020101042051B6FC0EF1946F3A86D2A4C9557C5D8ECFF13113B4131089C5C48BF7291FFDF530250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420A1A7B2285B954DD053253C1D851709F7380731176CC9EB1123546439C704108A302502010F04205265ECB286F406D93EC5B8965659D45450D8DA1A97575DEF4EFC7303C7408730302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA082044D308204493082027DA00302010202060130846F2B3E304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203047310B3009060355040613024445310D300B060355040A0C044554534931173015060355040B0C0E436F756E747279205369676E65723110300E06035504030C0745545349204353301E170D3131303631323135313835365A170D3132303630363135313835365A3048310B3009060355040613024445310D300B060355040A0C044554534931183016060355040B0C0F446F63756D656E74205369676E65723110300E06035504030C074554534920445330820122300D06092A864886F70D01010105000382010F003082010A0282010100D986CFA346CDE37F6F900ADDAE5D91CA955FF02AAB8AD8BBF4EF6D2A7BD25EB67F6EA56F2C4F2BEA026E66569C9E242607B19ECC84F8E441CE973D8BD76F7C4D2897E1D8CBF937C29272EF68FB33E46CBF02969CACD84A778F6FDBEE5C0C06E5FF5BAEF3BB0EF2FC2B66CCF768F0970E9A5D93D5B506C31B41BF6AFB0A3840DF287EE3BEE348FA05D47F855486851A6D966E2DC002EF028FA2491BA25783C74D5CE839B2C6F6A43A84502353C0C0C08F027A4AD1FB5431FC11D097EF228B5721D02C264A7F961A8C441F266BC755FF36C3E442DD674909FFD21129623707AFC0F1F701BF1C586CB6FDF5321F50ACDE6241E4684FEAB8D7958843656358AB3D510203010001A3523050301F0603551D23041830168014CEA56178E7A1585B3AEF1E25EF9EC82940158D10301D0603551D0E04160414731FE7AEC52D7A75624F8DC4D794CEA4709EFB5A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201200382018100B15A5DB7E7280F1A15070817E6E877079741910A33C7C99F783CB61003A45120B6348545FD588C676D96BBE9AF609BDEE9D633A1C1B5C302F4B24C299C5B27DA68A84756569186EC9C417F40B19BC6F9639FC0B7DEFA77526DABBCE014D9C3578718373CB4289D0365F2B78B52EB274198F4820C33EC0496EBFB16960D17A49EBA1859E4A0737EF6C91AA776B712DB2DF9A44933FC5AFA96E532ABF896C1C1CD0076A6AF0746FEDC212C8F41B257F45626C064EACD3FC244232C0689768F0A30C0FA4D46422736AA26C1FA6D880623EB86C04920312D72B044985AC03A0A6EA3F4EFF784C7FD62BB751D240E7A939DBFFAAE999FCB237643B3A032078D2471F78C38487A6860E0C1CD23B796E12484C32B737E13A0F44E3BAF632204440150F035C09B1827BF87692C766E93AFEC3616B984916BC43006EFA5BB92ACD25344095D276FB615E38D0311BB3B849FD0E5269B8B0A85E7FC649A4B5C2BFE05A3D22B3EEBA432F34D0883A6AED5E119CB030396714D19E4D93E006EDFF3DD6E177C40318201FA308201F602010130513047310B3009060355040613024445310D300B060355040A0C044554534931173015060355040B0C0E436F756E747279205369676E65723110300E06035504030C074554534920435302060130846F2B3E300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B07B3583840A50F05E0B0AC5C8310629314B377D2F843FC82110A3B072BE5227304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100599622056634871C86D5161CCA6AF851F14148E0E7EB79B1186DD6BEDF5BD0343EDB6C49B664E9FB459E742CA83358CE83E6B225A0CBFA7C3E9C6AF6D5BC2F4040DD47BF24CACB06FBDD933EEFAD360542656E1F65E0010B8EAE4DA084FC7B78ECB0CED647580BD1E8E2F8660252721E6DC8BD83A8EBE27F780FDBCBEA49D24C6A8A596BA4F4673A04409F2C1EA1CBC6802C9748DD5B2DF042391BA87650447C7E3BAD05553ACDEB96972E3907F425571D767F82219E02BB8839E7FEC9CFE07DCB88B5831A511383DADF5C7C0CB1CE1BD6C2B8B02C2C20DB27402DD3B0CE171993C417D065DD9A0B278E641CF51BABBCCA1128A400ED4AB7C0FD531E4D1E475C')
        sod = ef.SOD.load(tv_sod)
        tv_dg14 = ef.DG14.load(bytes.fromhex('6E82014A3182014630820122060904007F000702020102308201133081D406072A8648CE3D02013081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101033A00047BEAAD1C2738A816525EE6B96823028B975E6EA1A2284105A6AAE2A42A2D83EFF9FAC24EE4ECCFCB1214AB3AD10C01782D465532B8D27E29300F060A04007F00070202030201020101300D060804007F0007020202020101'))
        assert sod.ldsSecurityObject.contains(tv_dg14) == False
        sod.verify(sod.signers[0], sod.getDscCertificate(sod.signers[0]))

    # Test vector taken from https://www.etsi.org/
    # https://www.etsi.org/deliver/etsi_tr/103200_103299/103200/01.01.01_60/tr_103200v010101p.pdf
    # https://docbox.etsi.org/MTS/MTS/05-CONTRIBUTIONS/2011/MTS(11)0044_DMIMTS-00127_ePassport_Prototype_Platform.zip
    # ePassport_Data/CFG/DFLT/EACAA/EF_SOD.bin
    #
    # Modified country code in MRZ from 'D' to 'ES'
    tv_sod = bytes.fromhex('778207903082078C06092A864886F70D010702A082077D30820779020103310F300D06096086480165030402010500308201120606678108010101A0820106048201023081FF020100300D060960864801650304020105003081EA3025020101042051B6FC0EF1946F3A86D2A4C9557C5D8ECFF13113B4131089C5C48BF7291FFDF530250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420A1A7B2285B954DD053253C1D851709F6380731176CC9EB1123546439C704108A302502010F04205265ECB286F406D93EC5B8965659D45450D8DA1A97575DEF4EFC7303C7408730302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA082044D308204493082027DA00302010202060130846F2B3E304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203047310B3009060355040613024445310D300B060355040A0C044554534931173015060355040B0C0E436F756E747279205369676E65723110300E06035504030C0745545349204353301E170D3131303631323135313835365A170D3132303630363135313835365A3048310B3009060355040613024445310D300B060355040A0C044554534931183016060355040B0C0F446F63756D656E74205369676E65723110300E06035504030C074554534920445330820122300D06092A864886F70D01010105000382010F003082010A0282010100D986CFA346CDE37F6F900ADDAE5D91CA955FF02AAB8AD8BBF4EF6D2A7BD25EB67F6EA56F2C4F2BEA026E66569C9E242607B19ECC84F8E441CE973D8BD76F7C4D2897E1D8CBF937C29272EF68FB33E46CBF02969CACD84A778F6FDBEE5C0C06E5FF5BAEF3BB0EF2FC2B66CCF768F0970E9A5D93D5B506C31B41BF6AFB0A3840DF287EE3BEE348FA05D47F855486851A6D966E2DC002EF028FA2491BA25783C74D5CE839B2C6F6A43A84502353C0C0C08F027A4AD1FB5431FC11D097EF228B5721D02C264A7F961A8C441F266BC755FF36C3E442DD674909FFD21129623707AFC0F1F701BF1C586CB6FDF5321F50ACDE6241E4684FEAB8D7958843656358AB3D510203010001A3523050301F0603551D23041830168014CEA56178E7A1585B3AEF1E25EF9EC82940158D10301D0603551D0E04160414731FE7AEC52D7A75624F8DC4D794CEA4709EFB5A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201200382018100B15A5DB7E7280F1A15070817E6E877079741910A33C7C99F783CB61003A45120B6348545FD588C676D96BBE9AF609BDEE9D633A1C1B5C302F4B24C299C5B27DA68A84756569186EC9C417F40B19BC6F9639FC0B7DEFA77526DABBCE014D9C3578718373CB4289D0365F2B78B52EB274198F4820C33EC0496EBFB16960D17A49EBA1859E4A0737EF6C91AA776B712DB2DF9A44933FC5AFA96E532ABF896C1C1CD0076A6AF0746FEDC212C8F41B257F45626C064EACD3FC244232C0689768F0A30C0FA4D46422736AA26C1FA6D880623EB86C04920312D72B044985AC03A0A6EA3F4EFF784C7FD62BB751D240E7A939DBFFAAE999FCB237643B3A032078D2471F78C38487A6860E0C1CD23B796E12484C32B737E13A0F44E3BAF632204440150F035C09B1827BF87692C766E93AFEC3616B984916BC43006EFA5BB92ACD25344095D276FB615E38D0311BB3B849FD0E5269B8B0A85E7FC649A4B5C2BFE05A3D22B3EEBA432F34D0883A6AED5E119CB030396714D19E4D93E006EDFF3DD6E177C40318201FA308201F602010130513047310B3009060355040613024445310D300B060355040A0C044554534931173015060355040B0C0E436F756E747279205369676E65723110300E06035504030C074554534920435302060130846F2B3E300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B07B3583840A50F05E0B0AC5C8310629314B377D2F843FC82110A3B072BE5227304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100599622056634871C86D5161CCA6AF851F14148E0E7EB79B1186DD6BEDF5BD0343EDB6C49B664E9FB459E742CA83358CE83E6B225A0CBFA7C3E9C6AF6D5BC2F4040DD47BF24CACB06FBDD933EEFAD360542656E1F65E0010B8EAE4DA084FC7B78ECB0CED647580BD1E8E2F8660252721E6DC8BD83A8EBE27F780FDBCBEA49D24C6A8A596BA4F4673A04409F2C1EA1CBC6802C9748DD5B2DF042391BA87650447C7E3BAD05553ACDEB96972E3907F425571D767F82219E02BB8839E7FEC9CFE07DCB88B5831A511383DADF5C7C0CB1CE1BD6C2B8B02C2C20DB27402DD3B0CE171993C417D065DD9A0B278E641CF51BABBCCA1128A400ED4AB7C0FD531E4D1E475C')
    sod = ef.SOD.load(tv_sod)
    tv_dg1 = ef.DG1.load(bytes.fromhex('615B5F1F58503C53553C4D55535445524D414E4E3C3C4552494B413C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C433131543030324A4D3453553C3936303831323246313331303331373C3C3C3C3C3C3C3C3C3C3C3C3C3C3C36'))
    assert sod.ldsSecurityObject.contains(tv_dg1) == False
    sod.verify(sod.signers[0], sod.getDscCertificate(sod.signers[0]))

    # Test vector taken from https://www.etsi.org/
    # https://www.etsi.org/deliver/etsi_tr/103200_103299/103200/01.01.01_60/tr_103200v010101p.pdf
    # https://docbox.etsi.org/MTS/MTS/05-CONTRIBUTIONS/2011/MTS(11)0044_DMIMTS-00127_ePassport_Prototype_Platform.zip
    # ePassport_Data/CFG/DFLT/EACAA/EF_SOD.bin
    #
    # Modified modified public exponent of RSA public key in EF.DG15 from 010001 to 010002
    tv_sod = bytes.fromhex('778207903082078C06092A864886F70D010702A082077D30820779020103310F300D06096086480165030402010500308201120606678108010101A0820106048201023081FF020100300D060960864801650304020105003081EA3025020101042051B6FC0EF1946F3A86D2A4C9557C5D8ECFF13113B4131089C5C48BF7291FFDF530250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420A1A7B2285B954DD053253C1D851709F6380731176CC9EB1123546439C704108A302502010F04205265ECB286F406D93EC5B8965659D45450D8DA1A97575DEF4EFC7303C7408730302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA082044D308204493082027DA00302010202060130846F2B3E304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203047310B3009060355040613024445310D300B060355040A0C044554534931173015060355040B0C0E436F756E747279205369676E65723110300E06035504030C0745545349204353301E170D3131303631323135313835365A170D3132303630363135313835365A3048310B3009060355040613024445310D300B060355040A0C044554534931183016060355040B0C0F446F63756D656E74205369676E65723110300E06035504030C074554534920445330820122300D06092A864886F70D01010105000382010F003082010A0282010100D986CFA346CDE37F6F900ADDAE5D91CA955FF02AAB8AD8BBF4EF6D2A7BD25EB67F6EA56F2C4F2BEA026E66569C9E242607B19ECC84F8E441CE973D8BD76F7C4D2897E1D8CBF937C29272EF68FB33E46CBF02969CACD84A778F6FDBEE5C0C06E5FF5BAEF3BB0EF2FC2B66CCF768F0970E9A5D93D5B506C31B41BF6AFB0A3840DF287EE3BEE348FA05D47F855486851A6D966E2DC002EF028FA2491BA25783C74D5CE839B2C6F6A43A84502353C0C0C08F027A4AD1FB5431FC11D097EF228B5721D02C264A7F961A8C441F266BC755FF36C3E442DD674909FFD21129623707AFC0F1F701BF1C586CB6FDF5321F50ACDE6241E4684FEAB8D7958843656358AB3D510203010001A3523050301F0603551D23041830168014CEA56178E7A1585B3AEF1E25EF9EC82940158D10301D0603551D0E04160414731FE7AEC52D7A75624F8DC4D794CEA4709EFB5A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201200382018100B15A5DB7E7280F1A15070817E6E877079741910A33C7C99F783CB61003A45120B6348545FD588C676D96BBE9AF609BDEE9D633A1C1B5C302F4B24C299C5B27DA68A84756569186EC9C417F40B19BC6F9639FC0B7DEFA77526DABBCE014D9C3578718373CB4289D0365F2B78B52EB274198F4820C33EC0496EBFB16960D17A49EBA1859E4A0737EF6C91AA776B712DB2DF9A44933FC5AFA96E532ABF896C1C1CD0076A6AF0746FEDC212C8F41B257F45626C064EACD3FC244232C0689768F0A30C0FA4D46422736AA26C1FA6D880623EB86C04920312D72B044985AC03A0A6EA3F4EFF784C7FD62BB751D240E7A939DBFFAAE999FCB237643B3A032078D2471F78C38487A6860E0C1CD23B796E12484C32B737E13A0F44E3BAF632204440150F035C09B1827BF87692C766E93AFEC3616B984916BC43006EFA5BB92ACD25344095D276FB615E38D0311BB3B849FD0E5269B8B0A85E7FC649A4B5C2BFE05A3D22B3EEBA432F34D0883A6AED5E119CB030396714D19E4D93E006EDFF3DD6E177C40318201FA308201F602010130513047310B3009060355040613024445310D300B060355040A0C044554534931173015060355040B0C0E436F756E747279205369676E65723110300E06035504030C074554534920435302060130846F2B3E300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B07B3583840A50F05E0B0AC5C8310629314B377D2F843FC82110A3B072BE5227304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100599622056634871C86D5161CCA6AF851F14148E0E7EB79B1186DD6BEDF5BD0343EDB6C49B664E9FB459E742CA83358CE83E6B225A0CBFA7C3E9C6AF6D5BC2F4040DD47BF24CACB06FBDD933EEFAD360542656E1F65E0010B8EAE4DA084FC7B78ECB0CED647580BD1E8E2F8660252721E6DC8BD83A8EBE27F780FDBCBEA49D24C6A8A596BA4F4673A04409F2C1EA1CBC6802C9748DD5B2DF042391BA87650447C7E3BAD05553ACDEB96972E3907F425571D767F82219E02BB8839E7FEC9CFE07DCB88B5831A511383DADF5C7C0CB1CE1BD6C2B8B02C2C20DB27402DD3B0CE171993C417D065DD9A0B278E641CF51BABBCCA1128A400ED4AB7C0FD531E4D1E475C')
    sod = ef.SOD.load(tv_sod)
    tv_dg15 = ef.DG15.load(bytes.fromhex('6F81A230819F300D06092A864886F70D010101050003818D003081890281810095BDA8143635678427038D225E6F398B327F8AF02647B65C36E9FA8F4E7F8156364A231326F1EC1B9641B78822EC3014656D375C5F60641717F40F40B699DE3CCCB054550DD6DF2640022B9352701F2AB757E9A20FA605D309B6DDD7201F23CFDACC9EE299F187E9E71B650483DC4F6BC109F8FE8A2C2854C784057EE0E6F7670203010002'))
    assert sod.ldsSecurityObject.contains(tv_dg15) == False
