import hashlib
import asn1crypto.core as asn1
import asn1crypto.parser as asn1Parser


class LDSVersionInfo(asn1.Sequence):
    _fields = [
        ('ldsVersion', asn1.PrintableString),
        ('unicodeVersion', asn1.PrintableString),
    ]

class ElementaryFileError(ValueError):
    pass

class ElementaryFile(asn1.Asn1Value):
    _content_spec = None
    _str_rep = None

    def __init__(self, class_=None, tag=None, method=None, contents=None, spec=None, **kwargs):

        if spec:
            self._content_spec = spec

        super().__init__(class_=class_, tag=tag, contents=contents, *kwargs)
        self.method   = method
        self._content = None
        self._fp      = None

    def __str__(self):
        """
        Returns string representation of self i.e. EF(fp=XXXXXXXXXXXXXXXX)
        """
        if self._str_rep is None:
            self._str_rep = f'EF(fp={self.fingerprint})'
        return self._str_rep

    @classmethod
    def load(cls, encoded_data: bytes, strict=False): #pylint: disable=arguments-differ
        '''
        Loads a BER/DER-encoded byte string using the current class as the spec
        :param encoded_data:
            A byte string of BER or DER encoded data
        :param strict:
            A boolean indicating if trailing data should be forbidden - if so, a
            ValueError will be raised when trailing data exists
        :return:
            A instance of the current class
        '''

        class_, method, tag, header, contents, trailer = asn1Parser.parse(encoded_data, strict=strict) #pylint: disable=unused-variable
        value = cls(class_=class_, tag=tag, method=method, contents=contents)

        if cls.class_ is not None and value.class_ != cls.class_:
            raise ElementaryFileError("Invalid elementary file class, expected class '{}' got '{}'"
                .format(
                    asn1.CLASS_NUM_TO_NAME_MAP.get(cls.class_, cls.class_),
                    asn1.CLASS_NUM_TO_NAME_MAP.get(value.class_, value.class_)
            ))
        if cls.method is not None and value.method != cls.method:
            raise ElementaryFileError("Invalid elementary file method , expected method '{}' got '{}'"
                .format(
                    asn1.METHOD_NUM_TO_NAME_MAP.get(cls.method, cls.method),
                    asn1.METHOD_NUM_TO_NAME_MAP.get(value.method, value.method)
            ))

        if cls.tag is not None and value.tag != cls.tag:
            raise ElementaryFileError(f"Invalid elementary file tag, expected tag '{cls.tag}' got '{value.tag}'")

        # Force parsing of content. This is done in order for any invalid content to rise an exception
        value.content #pylint: disable=pointless-statement
        return value

    @property
    def fingerprint(self) -> str:
        """
        Returns hex str of the first 8 bytes of sha256 hash of self.
        """
        if self._fp is None:
            d = hashlib.sha256(self.dump()).digest()
            self._fp = d[0:8].hex().upper().rjust(16, '0')
        return self._fp

    @property
    def content(self):
        ''' Returns content object of a type content_type '''
        if self._content is None:
            self._parse_content()
        return self._content

    @property
    def native(self):
        '''
        The native Python data type representation of this value
        :return:
            A native representation of content object or None.
        '''

        if self.contents is None:
            return None

        if self.content is None:
            return self.contents
        return self.content.native

    def _parse_content(self):
        '''
        Parses the contents and generates Asn1Value content objects based on the
        definitions from _content_spec.
        :raises:
            ValueError - when an error occurs parsing content object
        '''

        self._content = None
        if self.contents is None:
            return

        if self._content_spec is not None:
            if not issubclass(self._content_spec, asn1.Asn1Value):
                raise ValueError(f'_content_spec must be of a Ans1Value type, not {self._content_spec!r}')

            try:
                self._content = self._content_spec.load(self.contents, strict=True)
                if isinstance(self._content, (asn1.Sequence, asn1.SequenceOf)):
                    self._content._parse_children(recurse=True) #pylint: disable=protected-access
            except (ValueError, TypeError) as e:
                from asn1crypto._types import type_name #pylint: disable=import-outside-toplevel
                self._content = None
                args   = e.args[1:]
                e.args = (e.args[0] + f'\n    while parsing {type_name(self)}',) + args
                raise
