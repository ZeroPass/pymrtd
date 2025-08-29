import asn1crypto.core as asn1

from .dg import DataGroup


class DataGroup7(asn1.OctetString, DataGroup):
    class_ = 7
    tag = 7

    def __init__(self, contents=None, **kwargs):
        self.image_data = []

        self.data = contents
        self.pos = 0
        self.body = self.data[self.pos :]

        super().__init__(contents=contents, **kwargs)

    @property
    def datagroup_type(self):
        return "DG7"

    @classmethod
    def load(cls, contents: bytes, strict=True):
        instance = cls(contents=contents)
        instance.parse()
        return instance

    def parse(self):
        tag = self.get_next_tag()
        self.verify_tag(tag, 0x02)
        _ = self.get_next_value()

        tag = self.get_next_tag()
        self.verify_tag(tag, 0x5F43)

        self.image_data = self.get_next_value()


class DG7(DataGroup):
    tag = 7
    _content_spec = DataGroup7

    @property
    def signature(self) -> DataGroup7:
        return self.content

    @property
    def native(self):
        return {"signature": self.signature}
