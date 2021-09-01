import pytest
from datetime import date

from pymrtd import ef
from pymrtd.ef.dg import DataGroupNumber

@pytest.mark.depends(on=[
    'tests/ef/ef_base_test.py::test_ef_base',
    'tests/ef/dg_base_test.py::test_dg_base',
    'tests/ef/mrz_test.py::test_mrz_parse',
])
def test_dg1():
    assert issubclass(ef.DG1, ef.DataGroup)

    #  Test vectors from Appendix A to the part 10 of ICAO 9393 p10 doc
    #  A.2.1
    tv_dg1 = bytes.fromhex('615D5F1F5A493C4E4C44584938353933354638363939393939393939303C3C3C3C3C3C3732303831343846313130383236384E4C443C3C3C3C3C3C3C3C3C3C3C3456414E3C4445523C535445454E3C3C4D415249414E4E453C4C4F55495345')
    dg1 = ef.DG1.load(tv_dg1)
    assert dg1.dump()                 == tv_dg1
    assert dg1.fingerprint            == "68629FEB5E8B7D0D"
    assert dg1.tag                    == 1
    assert dg1.number                 == DataGroupNumber(1)
    assert dg1.mrz.type               == 'td1'
    assert dg1.mrz.documentCode       == 'I'
    assert dg1.mrz.documentNumber     == 'XI85935F8'
    assert dg1.mrz.country            == 'NLD'
    assert dg1.mrz.nationality        == 'NLD'
    assert dg1.mrz.name               == 'MARIANNE LOUISE'
    assert dg1.mrz.surname            == 'VAN DER STEEN'
    assert dg1.mrz.gender             == 'F'
    assert dg1.mrz.dateOfBirth        == date( 1972, 8, 14 )
    assert dg1.mrz.dateOfExpiry       == date( 2011, 8, 26 )
    assert dg1.mrz.additionalData     == '999999990'
    assert dg1.mrz['optional_data_2'] == ''
    assert dg1.mrz.toJson()           == {
                                            'type'            : 'td1',
                                            'doc_code'        : 'I',
                                            'doc_number'      : 'XI85935F8',
                                            'date_of_expiry'  : date( 2011, 8, 26 ),
                                            'surname'         : 'VAN DER STEEN',
                                            'name'            : 'MARIANNE LOUISE',
                                            'date_of_birth'   : date( 1972, 8, 14 ),
                                            'gender'          : 'F',
                                            'country'         : 'NLD',
                                            'nationality'     : 'NLD',
                                            'additional_data' : '999999990'
                                         }

    #  Test vectors from Appendix A to the part 10 of ICAO 9393 p10 doc
    #  A.2.2 - Note: The serialized MRZ in doc is malformed!
    #                The data was modified:
    #                  - by removing extra '<' right of name field and optional data
    #                  - removed last invalid digit '4',
    #                  - CD for date of birth was changed to 1
    #                  - CD for date of expiry was changed to 2
    #                  - CD for doc. no. was changed to 2
    #                  - CD for composite was changed to0
    tv_dg1 = bytes.fromhex('614B5F1F48493C415441534D4954483C3C4A4F484E3C543C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3132333435363738393C484D44373430363232314D31303132333132303132323C3C3C30')
    dg1 = ef.DG1.load(tv_dg1)
    assert dg1.dump()                 == tv_dg1
    assert dg1.fingerprint            == "212982B17F733D8A"
    assert dg1.tag                    == 1
    assert dg1.number                 == DataGroupNumber(1)
    assert dg1.mrz.type               == 'td2'
    assert dg1.mrz.documentCode       == 'I'
    assert dg1.mrz.documentNumber     == '123456789012'
    assert dg1.mrz.country            == 'ATA'
    assert dg1.mrz.nationality        == 'HMD'
    assert dg1.mrz.name               == 'JOHN T'
    assert dg1.mrz.surname            == 'SMITH'
    assert dg1.mrz.gender             == 'M'
    assert dg1.mrz.dateOfBirth        == date( 1974, 6, 22 )
    assert dg1.mrz.dateOfExpiry       == date( 2010, 12, 31 )
    assert dg1.mrz.additionalData     == ''
    assert dg1.mrz.toJson()           == {
                                            'type'            : 'td2',
                                            'doc_code'        : 'I',
                                            'doc_number'      : '123456789012',
                                            'date_of_expiry'  :  date( 2010, 12, 31 ),
                                            'surname'         : 'SMITH',
                                            'name'            : 'JOHN T',
                                            'date_of_birth'   : date( 1974, 6, 22 ),
                                            'gender'          : 'M',
                                            'country'         : 'ATA',
                                            'nationality'     : 'HMD',
                                            'additional_data' : ''
                                         }

    # MRZ tv from ICAO 9303 part 4 Appendix B To Part 4 and prefixed with '615B' to simulate EF.DG1 file
    tv_dg1 = bytes.fromhex('615B5f1f58503c55544f4552494b53534f4e3c3c414e4e413c4d415249413c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c4c38393839303243333655544f3734303831323246313230343135395a45313834323236423c3c3c3c3c3130')
    dg1 = ef.DG1.load(tv_dg1)
    assert dg1.dump()                    == tv_dg1
    assert dg1.fingerprint               == "432BC07D1C637793"
    assert dg1.tag                       == 1
    assert dg1.number                    == DataGroupNumber(1)
    assert dg1.mrz.type                  == 'td3'
    assert dg1.mrz.documentCode          == 'P'
    assert dg1.mrz.country               == 'UTO'
    assert dg1.mrz.documentNumber        == 'L898902C3'
    assert dg1.mrz['document_number_cd'] == '6'
    assert dg1.mrz['optional_data']      == 'ZE184226B'
    assert dg1.mrz.additionalData        == 'ZE184226B'
    assert dg1.mrz['optional_data_cd']   == 1
    assert dg1.mrz.dateOfBirth           == date( 1974, 8, 12 )
    assert dg1.mrz['date_of_birth_cd']   == 2
    assert dg1.mrz.gender                == 'F'
    assert dg1.mrz.dateOfExpiry          == date( 2012, 4, 15 )
    assert dg1.mrz['date_of_expiry_cd']  == 9
    assert dg1.mrz.nationality           == 'UTO'
    assert dg1.mrz['composite_cd']       == 0
    assert dg1.mrz['name_identifiers']   == ( 'ERIKSSON', 'ANNA MARIA' )
    assert dg1.mrz.name                  == 'ANNA MARIA'
    assert dg1.mrz.surname               == 'ERIKSSON'
    assert dg1.mrz.toJson()              == {
                                                'type'            : 'td3',
                                                'doc_code'        : 'P',
                                                'doc_number'      : 'L898902C3',
                                                'date_of_expiry'  : date( 2012, 4, 15 ),
                                                'surname'         : 'ERIKSSON',
                                                'name'            : 'ANNA MARIA',
                                                'date_of_birth'   : date( 1974, 8, 12 ),
                                                'gender'          : 'F',
                                                'country'         : 'UTO',
                                                'nationality'     : 'UTO',
                                                'additional_data' : 'ZE184226B'
                                            }

    # Fuzz tests
    with pytest.raises(TypeError, match="contents must be a byte string, not NoneType"):
        ef.DG1.load(None)
    with pytest.raises(ValueError, match="Insufficient data - 2 bytes requested but only 0 available"):
        ef.DG1.load(bytes())
    with pytest.raises(ValueError, match="Insufficient data - 2 bytes requested but only 1 available"):
        ef.DG1.load(bytes.fromhex('00'))
    with pytest.raises(ValueError, match="Invalid elementary file class, expected class 'application' got 'universal'"):
        ef.DG1.load(bytes.fromhex('0000'))
    with pytest.raises(ValueError, match="Invalid elementary file class, expected class 'application' got 'universal'"):
        ef.DG1.load(bytes.fromhex('1C00'))
    with pytest.raises(ValueError, match="Invalid elementary file tag, expected tag '1' got '0'"):
        ef.DG1.load(bytes.fromhex('6000'))
