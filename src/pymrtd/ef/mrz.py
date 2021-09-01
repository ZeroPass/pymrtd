from enum import Enum
import asn1crypto.core as asn1
from datetime import datetime, date, timedelta
from typing import Optional

class DocumentType(Enum):
    """
    Enumeration of possible mayjor document types.
    """
    Passport = 'P' # DOC ICAO 9303-p4 4.2.2 specifies a capital letter 'P' as document code to define machine readable passport (MRP).
                   #    One additional capital letter can follow 'P' at the discretion of the issuing State or organization, to designate
                   #    other types of passports such as MRP issued to diplomatic staff, an MRP issued for travel on government business, or a passport issued for a special purpose.
                   #
                   #    Additional note: From doc ICAO 9303-p4 4.2.2.1 notes 'm':
                   #      "In documents other than passports, e.g. United Nations laissez-passer, seafarer’s identity document
                   #       or refugee travel document, the official title of the document shall be indicated  instead of “Passport”.
                   #       However, the first character of the document code shall be P"

class MachineReadableZone(asn1.OctetString):
    class_  = 1
    tag     = 31
    _parsed = None
    _type   = None

    @classmethod
    def load(cls, encoded_data: bytes, strict=False, **kwargs):
        v:MachineReadableZone = super().load(encoded_data, strict, **kwargs)
        clen = len(v.contents)
        # pylint: disable=protected-access
        if clen == 90:
            v._type = 'td1'
        elif clen == 72:
            v._type = 'td2'
        elif clen == 88:
            v._type = 'td3'
        else:
            raise ValueError("Unknown MRZ type")
        return v

    def __getitem__(self, key):
        return self.native[key]

    @property
    def country(self) -> str: # Issuing country
        return self['country']

    @property
    def date_of_birth(self) -> Optional[date]: # Could be None if date is not known
        return self['date_of_birth']

    @property
    def date_of_expiry(self) -> date:
        return self['date_of_expiry']

    @property
    def document_code(self) -> str:
        return self['document_code']

    @property
    def document_number(self) -> str:
        return self['document_number']

    @property
    def gender(self) -> str:
        return self['gender']

    @property
    def name(self) -> str:
        ni = self['name_identifiers']
        if len(ni) > 1:
            return ni[-1]
        return ""

    @property
    def nationality(self) -> str:
        return self['nationality']

    @property
    def native(self):
        if self._parsed is None:
            self.parse()
        return self._parsed

    @property
    def optional_data(self) -> str:
        if self.type == 'td1':
            return self['optional_data_1'] \
                if len(self['optional_data_1']) \
                else self['optional_data_2']
        return self['optional_data']

    @property
    def surname(self) -> str:
        ni = self['name_identifiers']
        if len(ni) > 0:
            return ni[0]
        return ""

    @property
    def type(self) -> str:
        return self._type #pylint: disable=maybe-no-member

    def to_json(self) -> dict:
        return {
            'type'            : self.type,
            'doc_code'        : self.document_code,
            'doc_number'      : self.document_number,
            'date_of_expiry'  : self.date_of_expiry,
            'surname'         : self.surname,
            'name'            : self.name,
            'date_of_birth'   : self.date_of_birth,
            'gender'          : self.gender,
            'country'         : self.country,
            'nationality'     : self.nationality,
            'additional_data' : self.optional_data
        }

    def parse(self):
        self._parsed = {}
        if self.type == 'td1':
            self._parse_td1()
        elif self.type == 'td2':
            self._parse_td2()
        elif self.type == 'td3':
            self._parse_td3()
        else:
            raise ValueError("Cannot parse unknown MRZ type")

    def _parse_td1(self):
        self._parsed['document_code']      = self._read(0, 2)
        self._parsed['country']            = self._read(2, 3)
        self._parsed['document_number']    = self._read(5, 9)
        self._parsed['document_number_cd'] = self._read_with_filter(14, 1) # document number check digit, could be char '<'
        self._parsed['optional_data_1']    = self._read(15, 15)
        self._parsed['date_of_birth']      = self._read_date_of_birth(30, 6)
        self._parsed['date_of_birth_cd']   = self._read_int(36, 1) # document dob digit
        self._parsed['gender']             = self._read(37, 1)
        self._parsed['date_of_expiry']     = self._read_date_of_expiry(38, 6)
        self._parsed['date_of_expiry_cd']  = self._read_int(44, 1) # document doe digit
        self._parsed['nationality']        = self._read(45, 3)
        self._parsed['optional_data_2']    = self._read(48, 11)
        self._parsed['composite_cd']       = self._read_int(59, 1)
        self._parsed['name_identifiers']   = self._read_name_identifiers(60, 30)
        self._parseExtendedDocumentNumber()

    def _parse_td2(self):
        self._parsed['document_code']      = self._read(0, 2)
        self._parsed['country']            = self._read(2, 3)
        self._parsed['name_identifiers']   = self._read_name_identifiers(5, 31)
        self._parsed['document_number']    = self._read(36, 9)
        self._parsed['document_number_cd'] = self._read_with_filter(45, 1) # document number check digit
        self._parsed['nationality']        = self._read(46, 3)
        self._parsed['date_of_birth']      = self._read_date_of_birth(49, 6)
        self._parsed['date_of_birth_cd']   = self._read_int(55, 1) # document dob digit
        self._parsed['gender']             = self._read(56, 1)
        self._parsed['date_of_expiry']     = self._read_date_of_expiry(57, 6)
        self._parsed['date_of_expiry_cd']  = self._read_int(63, 1) # document doe digit
        self._parsed['optional_data']      = self._read(64, 7)
        self._parsed['composite_cd']       = self._read_int(71, 1)
        self._parseExtendedDocumentNumber()

    def _parse_td3(self):
        self._parsed['document_code']      = self._read(0, 2)
        self._parsed['country']            = self._read(2, 3)
        self._parsed['name_identifiers']   = self._read_name_identifiers(5, 39)
        self._parsed['document_number']    = self._read(44, 9)
        self._parsed['document_number_cd'] = self._read_with_filter(53, 1) # document number check digit
        self._parsed['nationality']        = self._read(54, 3)
        self._parsed['date_of_birth']      = self._read_date_of_birth(57, 6)
        self._parsed['date_of_birth_cd']   = self._read_int(63, 1) # document dob digit
        self._parsed['gender']             = self._read(64, 1)
        self._parsed['date_of_expiry']     = self._read_date_of_expiry(65, 6)
        self._parsed['date_of_expiry_cd']  = self._read_int(71, 1) # document doe digit
        self._parsed['optional_data']      = self._read(72, 14)
        self._parsed['optional_data_cd']   = self._read_int(86, 1)
        self._parsed['composite_cd']       = self._read_int(87, 1)

    def _parseExtendedDocumentNumber(self):
        # doc 9303 p10 page 30
        fn_opt_data = 'optional_data_1' if self.type == 'td1' else 'optional_data'
        if self._parsed['document_number_cd'] == '<' and len(self._parsed[fn_opt_data]) > 0:
            self._parsed['document_number']   += self._parsed[fn_opt_data][:-1]
            self._parsed['document_number_cd'] = self._parsed[fn_opt_data][-1]
            self._parsed[fn_opt_data]          = ""

    def _read_with_filter(self, idx, len):
        return self.contents[idx: idx + len].decode('ascii')

    def _read(self, idx, len):
        return self._read_with_filter(idx, len).rstrip('<')

    def _read_int(self, idx, len):
        return int(self._read(idx, len))

    def _read_date(self, idx, len):
        date = self._read(idx, len)
        if '<' in date: # In case of unknown date of birth
            return None
        return datetime.strptime(date, '%y%m%d').date()

    def _read_date_of_birth(self, idx, len):
        date = self._read_date(idx, len)
        if date is not None and date > datetime.today().date(): # reduce date for 100 years if greater then current date
            days_per_year = 365.25
            date -= timedelta(days=(100 * days_per_year))
        return date

    def _read_date_of_expiry(self, idx, len):
        date = self._read_date(idx, len)
        if date is None:
            raise ValueError('Invalid date of expiry in MRZ data')
        return date

    def _read_name_identifiers(self, idx, size):
        name_field = self._read(idx, size)
        ids = name_field.split('<<')
        for i in range(0, len(ids)):
            ids[i] = ids[i].replace('<', ' ')
        return tuple(ids)
