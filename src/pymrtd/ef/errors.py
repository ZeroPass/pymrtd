class NFCPassportReaderError(Exception):
    INVALID_DATA = "InvalidData"
    INVALID_TAG = "InvalidTag"
    INVALID_LENGTH = "InvalidLength"
    UNKNOWN_IMAGE_FORMAT = "UnknownImageFormat"

    def __init__(self, message=""):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message
