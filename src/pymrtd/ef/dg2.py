import asn1crypto.core as asn1
from .errors import NFCPassportReaderError


class DataGroup2(asn1.OctetString):
    class_ = 2
    tag = 21

    def __init__(self, contents=None, **kwargs):
        self.nr_images = 0
        self.version_number = 0
        self.length_of_record = 0
        self.number_of_facial_images = 0
        self.facial_record_data_length = 0
        self.nr_feature_points = 0
        self.gender = 0
        self.eye_color = 0
        self.hair_color = 0
        self.feature_mask = 0
        self.expression = 0
        self.pose_angle = 0
        self.pose_angle_uncertainty = 0
        self.face_image_type = 0
        self.image_data_type = 0
        self.image_width = 0
        self.image_height = 0
        self.image_color_space = 0
        self.source_type = 0
        self.device_type = 0
        self.quality = 0
        self.image_data = []

        self.data = contents
        self.pos = 0
        self.body = self.data[self.pos :]

        super().__init__(contents=contents, **kwargs)

    @property
    def datagroup_type(self):
        return "DG2"

    @classmethod
    def load(cls, contents: bytes, strict=True):
        instance = cls(contents=contents)
        instance.parse()
        return instance

    def parse(self):
        tag = self.get_next_tag()
        self.verify_tag(tag, 0x7F61)
        self.get_next_length()

        # Tag should be 0x02
        tag = self.get_next_tag()
        self.verify_tag(tag, 0x02)
        value = self.get_next_value()
        self.nr_images = int(value[0])

        # Next tag is 0x7F60
        tag = self.get_next_tag()
        self.verify_tag(tag, 0x7F60)
        self.get_next_length()

        # Next tag is 0xA1 (Biometric Header Template) - don't care about this
        tag = self.get_next_tag()
        self.verify_tag(tag, 0xA1)
        self.get_next_value()

        # Now we get to the good stuff - next tag is either 5F2E or 7F2E
        tag = self.get_next_tag()
        self.verify_tag(tag, [0x5F2E, 0x7F2E])
        value = self.get_next_value()
        self.parse_iso19794_5(value)

    def parse_iso19794_5(self, data: bytes):
        if not (
            data[0] == 0x46 and data[1] == 0x41 and data[2] == 0x43 and data[3] == 0x00
        ):
            raise NFCPassportReaderError(NFCPassportReaderError.INVALID_DATA)

        offset = 4
        self.version_number = self.bin_to_int(data, offset, 4)
        offset += 4
        self.length_of_record = self.bin_to_int(data, offset, 4)
        offset += 4
        self.number_of_facial_images = self.bin_to_int(data, offset, 2)
        offset += 2

        self.facial_record_data_length = self.bin_to_int(data, offset, 4)
        offset += 4
        self.nr_feature_points = self.bin_to_int(data, offset, 2)
        offset += 2
        self.gender = self.bin_to_int(data, offset, 1)
        offset += 1
        self.eye_color = self.bin_to_int(data, offset, 1)
        offset += 1
        self.hair_color = self.bin_to_int(data, offset, 1)
        offset += 1
        self.feature_mask = self.bin_to_int(data, offset, 3)
        offset += 3
        self.expression = self.bin_to_int(data, offset, 2)
        offset += 2
        self.pose_angle = self.bin_to_int(data, offset, 3)
        offset += 3
        self.pose_angle_uncertainty = self.bin_to_int(data, offset, 3)
        offset += 3

        # Skip the feature points, 8 bytes per point
        offset += self.nr_feature_points * 8

        self.face_image_type = self.bin_to_int(data, offset, 1)
        offset += 1
        self.image_data_type = self.bin_to_int(data, offset, 1)
        offset += 1
        self.image_width = self.bin_to_int(data, offset, 2)
        offset += 2
        self.image_height = self.bin_to_int(data, offset, 2)
        offset += 2
        self.image_color_space = self.bin_to_int(data, offset, 1)
        offset += 1
        self.source_type = self.bin_to_int(data, offset, 1)
        offset += 1
        self.device_type = self.bin_to_int(data, offset, 2)
        offset += 2
        self.quality = self.bin_to_int(data, offset, 2)
        offset += 2

        jpeg_header = bytes(
            [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]
        )
        jpeg2000_bitmap_header = bytes(
            [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A]
        )
        jpeg2000_codestream_bitmap_header = bytes([0xFF, 0x4F, 0xFF, 0x51])

        if len(data) < offset + len(jpeg2000_codestream_bitmap_header):
            raise NFCPassportReaderError(NFCPassportReaderError.UNKNOWN_IMAGE_FORMAT)

        if not (
            data[offset : offset + len(jpeg_header)] == jpeg_header
            or data[offset : offset + len(jpeg2000_bitmap_header)]
            == jpeg2000_bitmap_header
            or data[offset : offset + len(jpeg2000_codestream_bitmap_header)]
            == jpeg2000_codestream_bitmap_header
        ):
            raise NFCPassportReaderError(NFCPassportReaderError.UNKNOWN_IMAGE_FORMAT)

        self.image_data = list(data[offset:])

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
