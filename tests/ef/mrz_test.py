import pytest
from pymrtd import ef
from datetime import date

def _td_as_der(td) -> bytes:
    td = "".join(f'{ord(c):02x}' for c in td)
    td = f'5F1F{int(len(td) /2):02x}{td}'
    return bytes.fromhex(td)

def test_mrz_parse():
    # tv from ICAO 9303 part 10 A.2.1
    tv  = _td_as_der("I<NLDXI85935F86999999990<<<<<<7208148F1108268NLD<<<<<<<<<<<4VAN<DER<STEEN<<MARIANNE<LOUISE")
    mrz = ef.MachineReadableZone.load(tv)
    assert mrz.dump()                   == tv
    assert mrz.type                     == 'td1'
    assert mrz.documentCode             == 'I'
    assert mrz.country                  == 'NLD'
    assert mrz.documentNumber           == 'XI85935F8'
    assert mrz['document_number_cd']    == '6'
    assert mrz['optional_data_1']       == '999999990'
    assert mrz.additionalData           == '999999990'
    assert mrz.dateOfBirth              == date( 1972, 8, 14 )
    assert mrz['date_of_birth_cd']      == 8
    assert mrz.gender                   == 'F'
    assert mrz.dateOfExpiry             == date( 2011, 8, 26 )
    assert mrz['date_of_expiry_cd']     == 8
    assert mrz.nationality              == 'NLD'
    assert mrz['optional_data_2']       == ''
    assert mrz['composite_cd']          == 4
    assert mrz['name_identifiers']      == ( 'VAN DER STEEN', 'MARIANNE LOUISE' )
    assert mrz.name                     == 'MARIANNE LOUISE'
    assert mrz.surname                  == 'VAN DER STEEN'
    assert mrz.toJson()                 == {
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

    # tv from ICAO 9303 part 11 Appendix D to Part 11 Section D.2
    tv  = _td_as_der("I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8")
    mrz = ef.MachineReadableZone.load(tv)
    assert mrz.dump()                   == tv
    assert mrz.type                     == 'td2'
    assert mrz.documentCode             == 'I'
    assert mrz.country                  == 'UTO'
    assert mrz.documentNumber           == 'D23145890734'
    assert mrz['document_number_cd']    == '9'
    assert mrz['optional_data']         == ''
    assert mrz.additionalData           == ''
    assert mrz.dateOfBirth              == date( 1934, 7, 12 )
    assert mrz['date_of_birth_cd']      == 7
    assert mrz.gender                   == 'M'
    assert mrz.dateOfExpiry             == date( 1995, 7, 12 )
    assert mrz['date_of_expiry_cd']     == 2
    assert mrz.nationality              == 'UTO'
    assert mrz['composite_cd']          == 8
    assert mrz['name_identifiers']      == ( 'STEVENSON', 'PETER JOHN' )
    assert mrz.name                     == 'PETER JOHN'
    assert mrz.surname                  == 'STEVENSON'
    assert mrz.toJson()                 == {
                                            'type'            : 'td2',
                                            'doc_code'        : 'I',
                                            'doc_number'      : 'D23145890734',
                                            'date_of_expiry'  : date( 1995, 7, 12 ),
                                            'surname'         : 'STEVENSON',
                                            'name'            : 'PETER JOHN',
                                            'date_of_birth'   : date( 1934, 7, 12 ),
                                            'gender'          : 'M',
                                            'country'         : 'UTO',
                                            'nationality'     : 'UTO',
                                            'additional_data' : ''
                                           }

    # tv from ICAO 9303 part 4 Appendix B To Part 4
    tv  = _td_as_der("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10")
    mrz = ef.MachineReadableZone.load(tv)
    assert mrz.dump()                   == tv
    assert mrz.type                     == 'td3'
    assert mrz.documentCode             == 'P'
    assert mrz.country                  == 'UTO'
    assert mrz.documentNumber           == 'L898902C3'
    assert mrz['document_number_cd']    == 6
    assert mrz['optional_data']         == 'ZE184226B'
    assert mrz.additionalData           == 'ZE184226B'
    assert mrz['optional_data_cd']      == 1
    assert mrz.dateOfBirth              == date( 1974, 8, 12 )
    assert mrz['date_of_birth_cd']      == 2
    assert mrz.gender                   == 'F'
    assert mrz.dateOfExpiry             == date( 2012, 4, 15 )
    assert mrz['date_of_expiry_cd']     == 9
    assert mrz.nationality              == 'UTO'
    assert mrz['composite_cd']          == 0
    assert mrz['name_identifiers']      == ( 'ERIKSSON', 'ANNA MARIA' )
    assert mrz.name                     == 'ANNA MARIA'
    assert mrz.surname                  == 'ERIKSSON'
    assert mrz.toJson()                 == {
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

    # tv from BSI TR-03105_Part5-1 - 4.4 Configuration of default EAC+AA passport
    # https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03105/TR-03105_Part5-1.pdf
    # Note: The optional data cd was changed to 0 from '<'
    tv  = _td_as_der("P<D<<MUSTERMANN<<ERIKA<<<<<<<<<<<<<<<<<<<<<<C11T002JM4D<<9608122F2310314<<<<<<<<<<<<<<04")
    mrz = ef.MachineReadableZone.load(tv)
    assert mrz.dump()                   == tv
    assert mrz.type                     == 'td3'
    assert mrz.documentCode             == 'P'
    assert mrz.country                  == 'D'
    assert mrz.documentNumber           == 'C11T002JM'
    assert mrz['document_number_cd']    == 4
    assert mrz['optional_data']         == ''
    assert mrz.additionalData           == ''
    assert mrz['optional_data_cd']      == 0
    assert mrz.dateOfBirth              == date( 1996, 8, 12 )
    assert mrz['date_of_birth_cd']      == 2
    assert mrz.gender                   == 'F'
    assert mrz.dateOfExpiry             == date( 2023, 10, 31 )
    assert mrz['date_of_expiry_cd']     == 4
    assert mrz.nationality              == 'D'
    assert mrz['composite_cd']          == 4
    assert mrz['name_identifiers']      == ( 'MUSTERMANN', 'ERIKA' )
    assert mrz.name                     == 'ERIKA'
    assert mrz.surname                  == 'MUSTERMANN'
    assert mrz.toJson()                 == {
                                            'type'            : 'td3',
                                            'doc_code'        : 'P',
                                            'doc_number'      : 'C11T002JM',
                                            'date_of_expiry'  : date( 2023, 10, 31 ),
                                            'surname'         : 'MUSTERMANN',
                                            'name'            : 'ERIKA',
                                            'date_of_birth'   : date( 1996, 8, 12 ),
                                            'gender'          : 'F',
                                            'country'         : 'D',
                                            'nationality'     : 'D',
                                            'additional_data' : ''
                                           }

    # Custom test vector
    tv  = _td_as_der("P<D<<SCHMIDT<<FINN<<<<<<<<<<<<<<<<<<<<<<<<<<AA89BXHZ56D<<7503201M2511188<<<<<<<<<<<<<<<8")
    mrz = ef.MachineReadableZone.load(tv)
    assert mrz.dump()                   == tv
    assert mrz.type                     == 'td3'
    assert mrz.documentCode             == 'P'
    assert mrz.country                  == 'D'
    assert mrz.documentNumber           == 'AA89BXHZ5'
    assert mrz['document_number_cd']    == 6
    assert mrz['optional_data']         == ''
    assert mrz.additionalData           == ''
    assert mrz['optional_data_cd']      == 0
    assert mrz.dateOfBirth              == date( 1975, 3, 20 )
    assert mrz['date_of_birth_cd']      == 1
    assert mrz.gender                   == 'M'
    assert mrz.dateOfExpiry             == date( 2025, 11, 18 )
    assert mrz['date_of_expiry_cd']     == 8
    assert mrz.nationality              == 'D'
    assert mrz['composite_cd']          == 8
    assert mrz['name_identifiers']      == ( 'SCHMIDT', 'FINN' )
    assert mrz.name                     == 'FINN'
    assert mrz.surname                  == 'SCHMIDT'
    assert mrz.toJson()                 == {
                                            'type'            : 'td3',
                                            'doc_code'        : 'P',
                                            'doc_number'      : 'AA89BXHZ5',
                                            'date_of_expiry'  : date( 2025, 11, 18 ),
                                            'surname'         : 'SCHMIDT',
                                            'name'            : 'FINN',
                                            'date_of_birth'   : date( 1975, 3, 20 ),
                                            'gender'          : 'M',
                                            'country'         : 'D',
                                            'nationality'     : 'D',
                                            'additional_data' : ''
                                           }

    # Fuzz tests
    with pytest.raises(TypeError, match="encoded_data must be a byte string, not str"):
        ef.MachineReadableZone.load('')
    with pytest.raises(ValueError, match="Insufficient data - 2 bytes requested but only 0 available"):
        ef.MachineReadableZone.load(bytes())
    with pytest.raises(ValueError, match="Unknown MRZ type"):
        ef.MachineReadableZone.load(_td_as_der(''))
    with pytest.raises(ValueError, match="Unknown MRZ type"):
        ef.MachineReadableZone.load(_td_as_der('P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<'))
    with pytest.raises(ValueError, match="Unknown MRZ type"):
        ef.MachineReadableZone.load(_td_as_der('XP<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10'))
