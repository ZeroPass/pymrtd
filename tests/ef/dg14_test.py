import pytest
from pymrtd import ef
from pymrtd.ef.dg import *

@pytest.mark.depends(on=[
    'tests/ef/ef_base_test.py::test_ef_base',
    'tests/ef/dg_base_test.py::test_dg_base',
])
def test_dg14():
    assert issubclass(ef.DG14, ef.DataGroup)

    # Test vector taken from German BSI TR-03105-5 ReferenceDataSet
    # https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03105/BSI_TR-03105-5_ReferenceDataSet_zip.html
    # Datagroup14.bin
    tv_dg14 = bytes.fromhex('6E82014A3182014630820122060904007F000702020102308201133081D406072A8648CE3D02013081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101033A0004A847F020F71DF33D386BE7C9223A354D6AC7727018B26E281C6FFB96A83B142AAF303C23F2BCF2CDE4706C14E45914A9BE42C15BCB67A01F300F060A04007F00070202030201020101300D060804007F0007020202020101')
    dg14    = ef.DG14.load(tv_dg14)
    assert dg14.dump()                == tv_dg14
    assert dg14.fingerprint           == "CF5004FFCCD64E1A"
    assert dg14.tag                   == 14
    assert dg14.number                == DataGroupNumber(14)
    assert dg14.aaInfo                == None
    assert dg14.aaSignatureAlgo       == None
    assert len(dg14.content.children) == 3
    assert dg14.content.children[0].contents == bytes.fromhex('060904007F000702020102308201133081D406072A8648CE3D02013081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101033A0004A847F020F71DF33D386BE7C9223A354D6AC7727018B26E281C6FFB96A83B142AAF303C23F2BCF2CDE4706C14E45914A9BE42C15BCB67A01F')
    assert dg14.content.children[1].chosen.contents == ChipAuthenticationInfo({
        'protocol' : ChipAuthenticationInfoId.unmap('ca_ecdh_3des_cbc_cbc'),
        'version' : 1
    }).contents
    assert dg14.content.children[2].contents == bytes.fromhex('060804007F0007020202020101')

    # Test vector taken from https://www.etsi.org/
    # https://www.etsi.org/deliver/etsi_tr/103200_103299/103200/01.01.01_60/tr_103200v010101p.pdf
    # https://docbox.etsi.org/MTS/MTS/05-CONTRIBUTIONS/2011/MTS(11)0044_DMIMTS-00127_ePassport_Prototype_Platform.zip
    # ePassport_Data/CFG/DFLT/EAC/EF_DG14.bin
    tv_dg14 = bytes.fromhex('6E82014A3182014630820122060904007F000702020102308201133081D406072A8648CE3D02013081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101033A00047BEAAD1C2738A816525EE6B96823028B975E6EA1A2284105A6AAE2A42A2D83EFF9FAC24EE4ECCFCB1214AB3AD10C01782D465532B8D27E29300F060A04007F00070202030201020101300D060804007F0007020202020101')
    dg14    = ef.DG14.load(tv_dg14)
    assert dg14.dump()                == tv_dg14
    assert dg14.fingerprint           == "A1A7B2285B954DD0"
    assert dg14.tag                   == 14
    assert dg14.number                == DataGroupNumber(14)
    assert dg14.aaInfo                == None
    assert dg14.aaSignatureAlgo       == None
    assert len(dg14.content.children) == 3
    assert dg14.content.children[0].contents == bytes.fromhex('060904007F000702020102308201133081D406072A8648CE3D02013081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101033A00047BEAAD1C2738A816525EE6B96823028B975E6EA1A2284105A6AAE2A42A2D83EFF9FAC24EE4ECCFCB1214AB3AD10C01782D465532B8D27E29')
    assert dg14.content.children[1].chosen.contents == ChipAuthenticationInfo({
        'protocol' : ChipAuthenticationInfoId.unmap('ca_ecdh_3des_cbc_cbc'),
        'version' : 1
    }).contents
    assert dg14.content.children[2].contents == bytes.fromhex('060804007F0007020202020101')

    # Fuzz tests
    with pytest.raises(ValueError, match="pymrtd.ef.dg.ChipAuthenticationInfo version != 1"):
        # Test vector taken from https://www.etsi.org/
        # https://www.etsi.org/deliver/etsi_tr/103200_103299/103200/01.01.01_60/tr_103200v010101p.pdf
        # https://docbox.etsi.org/MTS/MTS/05-CONTRIBUTIONS/2011/MTS(11)0044_DMIMTS-00127_ePassport_Prototype_Platform.zip
        # ePassport_Data/CFG/EAC/LDS/F06/EF_DG14.bin
        tv_dg14 = bytes.fromhex('6E82014A3182014630820122060904007F000702020102308201133081D406072A8648CE3D02013081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101033A00043BAFA045BF1A7504CEC6EC8A6ACEC37BDDB86D0B558F926C24EA3DC83638DAE2BC09DC23579FF3CAFF445A91E9E02E83C592874010CC0B70300F060A04007F00070202030201020110300D060804007F0007020202020101')
        dg14    = ef.DG14.load(tv_dg14)
