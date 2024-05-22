import asn1crypto.core as asn1
from asn1crypto.util import int_from_bytes

from .base import ElementaryFile
from .errors import NFCPassportReaderError


class DataGroupNumber(asn1.Integer):
    min = 1  # DG min value
    max = 16  # DG max value

    _map = {
        1: "EF.DG1",
        2: "EF.DG2",
        3: "EF.DG3",
        4: "EF.DG4",
        5: "EF.DG5",
        6: "EF.DG6",
        7: "EF.DG7",
        8: "EF.DG8",
        9: "EF.DG9",
        10: "EF.DG10",
        11: "EF.DG11",
        12: "EF.DG12",
        13: "EF.DG13",
        14: "EF.DG14",
        15: "EF.DG15",
        16: "EF.DG16",
    }

    @property
    def value(self) -> int:
        return int_from_bytes(self.contents, signed=True)

    def __eq__(self, other) -> bool:
        if isinstance(other, int):
            return self.value == other
        if isinstance(other, DataGroupNumber):
            return super().__eq__(other)
        return False

    def __ne__(self, other) -> bool:
        return not self.__eq__(other)

    def set(self, value):
        if isinstance(value, int):
            if value == 21:  # DG2 tag
                value = 2
            elif value == 22:  # DG4 tag
                value = 4
            elif value not in DataGroupNumber._map:
                raise ValueError("Invalid data group number")
        super().set(value)

    def __hash__(self) -> int:
        return hash(self.value)


class DataGroup(ElementaryFile):
    class_ = 1
    method = 1

    def __str__(self):
        """
        Returns string representation of self i.e. EF.DG<No>(fp=XXXXXXXXXXXXXXXX)
        """
        if self._str_rep is None:
            self._str_rep = (
                super().__str__().replace("EF(", f"{self.number.native}(", 1)
            )
        return self._str_rep

    @property
    def number(self) -> DataGroupNumber:
        return DataGroupNumber(self.tag)

    def get_next_tag(self) -> int:
        tag = 0

        # Fix for some passports that may have invalid data - ensure that we do have data!
        if len(self.data) <= self.pos:
            raise NFCPassportReaderError(NFCPassportReaderError.INVALID_DATA)

        if self.bin_to_hex(self.data[self.pos : self.pos + 1]) & 0x0F == 0x0F:
            tag = self.bin_to_hex(self.data[self.pos : self.pos + 2])
            self.pos += 2
        else:
            tag = self.data[self.pos]
            self.pos += 1

        return tag

    def verify_tag(self, tag, valid_values):
        if isinstance(valid_values, list):
            if tag not in valid_values:
                raise NFCPassportReaderError(NFCPassportReaderError.INVALID_TAG)
        else:
            if tag != valid_values:
                raise NFCPassportReaderError("InvalidTag")

    def asn1_length(self, data: bytes) -> tuple:
        if data[0] < 0x80:
            return int(data[0]), 1
        if data[0] == 0x81:
            return int(data[1]), 2
        if data[0] == 0x82:
            val = int.from_bytes(data[1:3], byteorder="big")
            return val, 3
        raise NFCPassportReaderError(NFCPassportReaderError.INVALID_LENGTH)

    def get_next_length(self) -> int:
        end = self.pos + 4 if self.pos + 4 < len(self.data) else len(self.data)
        length, len_offset = self.asn1_length(self.data[self.pos : end])
        self.pos += len_offset
        return length

    def get_next_value(self) -> bytes:
        length = self.get_next_length()
        value = self.data[self.pos : self.pos + length]
        self.pos += length
        return value

    def bin_to_int(self, data: bytes, offset: int, length: int) -> int:
        return int.from_bytes(data[offset : offset + length], byteorder="big")

    def bin_to_hex(self, data: bytes) -> int:
        return int.from_bytes(data, byteorder="big")
