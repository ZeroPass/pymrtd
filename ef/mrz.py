import asn1crypto.core as asn1
from datetime import datetime, date

class MachineReadableZone(asn1.OctetString):
    class_ = 1
    tag    = 31
    _parsed = None

    @classmethod
    def load(cls, encoded_data: bytes, strict=False):
        v = super().load(encoded_data, strict)
        clen = len(v.contents) 
        if clen == 90:
            v.format = 'td1'
        elif clen == 72:
            v.format = 'td2'
        elif clen == 88:
            v.format = 'td3'
        else:
            ValueError("Unknown MRZ format")
        return v
    
    def __getitem__(self, key):
        return self.native[key]

    @property
    def country(self) -> str:
        return self['country']

    @property
    def date_of_birth(self) -> date:
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
        if self.format == 'td1':
            return self['optional_data_2']
        return self['optional_data']

    @property
    def surname(self) -> str:
        ni = self['name_identifiers']
        if len(ni) > 0:
            return ni[0]
        return ""

    def parse(self):
        self._parsed = {}
        if self.format == 'td1':
            self._parse_td1()
        elif self.format == 'td2':
            self._parse_td2()
        elif self.format == 'td3':
            self._parse_td3()
        else:
            ValueError("Cannot parse unknown MRZ format")

    def _parse_td1(self):
        self._parsed['document_code']         = self._read(0, 2)
        self._parsed['country']               = self._read(2, 3)
        self._parsed['document_number']       = self._read(5, 9)
        self._parsed['document_number_cd']    = self._read_with_filter(14, 1) # document number check digit, could be char '<'
        self._parsed['optional_data_1']       = self._read(15, 15)
        self._parsed['date_of_birth']         = self._read_date(30, 6)
        self._parsed['date_of_birth_cd']      = self._read_int(36, 1) # document dob digit
        self._parsed['sex']                   = self._read(37, 1)
        self._parsed['date_of_expiry']        = self._read_date(38, 6)
        self._parsed['date_of_expiry_cd']     = self._read_int(44, 1) # document doe digit
        self._parsed['nationality']           = self._read(45, 3)
        self._parsed['optional_data_2']       = self._read(48, 11)
        self._parsed['composite_check_digit'] = self._read_int(59, 1)
        self._parsed['name_identifiers']      = self._read_name_identifiers(60, 30)

        # doc 9303 p10 page 30
        if self._parsed['document_number_cd'] == '<' and len(self._parsed['optional_data_1']) > 0:
            self._parsed['document_number'] += self._parsed['optional_data_1'][:-1]
            self._parsed['document_number_cd'] = self._parsed['optional_data_1'][-1]
            self._parsed['optional_data_1'] = ""

    def _parse_td2(self):
        self._parsed['document_code']         = self._read(0, 2)
        self._parsed['country']               = self._read(2, 3)
        self._parsed['name_identifiers']      = self._read_name_identifiers(5, 31)
        self._parsed['document_number']       = self._read(36, 9)
        self._parsed['document_number_cd']    = self._read_with_filter(45, 1) # document number check digit
        self._parsed['nationality']           = self._read(46, 3)
        self._parsed['date_of_birth']         = self._read_date(49, 6)
        self._parsed['date_of_birth_cd']      = self._read_int(55, 1) # document dob digit
        self._parsed['sex']                   = self._read(56, 1)
        self._parsed['date_of_expiry']        = self._read_date(57, 6)
        self._parsed['date_of_expiry_cd']     = self._read_int(63, 1) # document doe digit
        self._parsed['optional_data']         = self._read(64, 7)
        self._parsed['composite_check_digit'] = self._read_int(71, 1)

    def _parse_td3(self):
        self._parsed['document_code']         = self._read(0, 2)
        self._parsed['country']               = self._read(2, 3)
        self._parsed['name_identifiers']      = self._read_name_identifiers(5, 39)
        self._parsed['document_number']       = self._read(44, 9)
        self._parsed['document_number_cd']    = self._read_with_filter(53, 1) # document number check digit
        self._parsed['nationality']           = self._read(54, 3)
        self._parsed['date_of_birth']         = self._read_date(57, 6)
        self._parsed['date_of_birth_cd']      = self._read_int(63, 1) # document dob digit
        self._parsed['sex']                   = self._read(64, 1)
        self._parsed['date_of_expiry']        = self._read_date(65, 6)
        self._parsed['date_of_expiry_cd']     = self._read_int(71, 1) # document doe digit
        self._parsed['optional_data']         = self._read(72, 14)
        self._parsed['check_digit']           = self._read_int(86, 1)
        self._parsed['composite_check_digit'] = self._read_int(87, 1)

    def _read_with_filter(self, idx, len):
        return self.contents[idx: idx + len].decode('ascii')

    def _read(self, idx, len):
        return self._read_with_filter(idx, len).rstrip('<')

    def _read_int(self, idx, len):
        return int(self._read(idx, len))

    def _read_date(self, idx, len):
        date = self._read(idx, len)
        return datetime.strptime(date, '%y%m%d').date()

    def _read_name_identifiers(self, idx, size):
        name_field = self._read(idx, size)
        ids = name_field.split('<<')
        for i in range(0, len(ids)):
            ids[i] = ids[i].replace('<', ' ')
        return tuple(ids)