import asn1crypto.core as asn1

from .dg import DataGroup


class DataGroup11(asn1.OctetString, DataGroup):
    class_ = 11
    tag = 11

    def __init__(self, contents=None, **kwargs):
        self.full_name = ""
        self.personal_number = ""
        self.date_of_birth = ""
        self.place_of_birth = ""
        self.address = ""
        self.telephone = ""
        self.profession = ""
        self.title = ""
        self.personal_summary = ""
        self.proof_of_citizenship = ""
        self.td_numbers = ""
        self.custody_info = ""

        self.data = contents
        self.pos = 0
        self.body = self.data[self.pos :]

        super().__init__(contents=contents, **kwargs)

    @property
    def datagroup_type(self):
        return "DG11"

    @classmethod
    def load(cls, contents: bytes, strict=True):
        instance = cls(contents=contents)
        instance.parse()
        return instance

    def parse(self):
        tag = self.get_next_tag()
        self.verify_tag(tag, 0x5C)
        _ = self.get_next_value()

        while self.pos < len(self.data):
            tag = self.get_next_tag()
            value = self.get_next_value()

            if tag == 0x5F0E:
                self.full_name = value.decode("utf-8")
            elif tag == 0x5F10:
                self.personal_number = value.decode("utf-8")
            elif tag == 0x5F11:
                self.place_of_birth = value.decode("utf-8")
            elif tag == 0x5F42:
                self.address = value.decode("utf-8")
            elif tag == 0x5F12:
                self.telephone = value.decode("utf-8")
            elif tag == 0x5F13:
                self.profession = value.decode("utf-8")
            elif tag == 0x5F14:
                self.title = value.decode("utf-8")
            elif tag == 0x5F15:
                self.personal_summary = value.decode("utf-8")
            elif tag == 0x5F16:
                self.proof_of_citizenship = value.decode("utf-8")
            elif tag == 0x5F17:
                self.td_numbers = value.decode("utf-8")
            elif tag == 0x5F18:
                self.custody_info = value.decode("utf-8")


class DG11(DataGroup):
    tag = 11
    _content_spec = DataGroup11

    @property
    def personal_info(self) -> DataGroup11:
        return self.content

    @property
    def native(self):
        return {"personal_info": self.personal_info}
