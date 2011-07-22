import copy
import pprint
import struct


TEST_PACKET = "\x00\x00\x12\x00.H\x00\x00\x00\x02\x85\t\xa0\x00\xd3\x01\x00\x00\x80\x00\x00\x00\xff\xff\xff\xff\xff\xffh\x7ft\xc6\x07\x9bh\x7ft\xc6\x07\x9b\xf02\x83q\x15\xef\xc9\x02\x00\x00d\x00\x01\x04\x00\x08WIRELESS\x01\x08\x82\x84\x8b\x96$0Hl\x03\x01\x06\x05\x04\x00\x01\x00\x00*\x01\x00/\x01\x002\x04\x0c\x12\x18`-\x1a|\x18\x1b\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00=\x16\x06\x00\x17\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\t\x00\x10\x18\x02\x03\xf0\x05\x00\x00\xdd\x18\x00P\xf2\x02\x01\x01\x80\x00\x03\xa4\x00\x00'\xa4\x00\x00BC^\x00b2/\x00\xdd\x1e\x00\x90L3|\x18\x1b\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\x1a\x00\x90L4\x06\x00\x17\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


class Field(object):
    """The smallest unit. Normally contained in `FieldCollection` objects."""

    SIZE_TABLE = {
        "c": 8,
        "b": 8,
        "B": 8,
        "h": 16,
        "H": 16,
        "i": 32,
        "I": 32,
        "l": 32,
        "L": 32,
        "q": 64,
        "Q": 64,
    }

    def __init__(self, name, data=None, start_bit=0):
        """Initialize a field."""
        self.name = name
        self.assign_data(data, start_bit)

    def __repr__(self):
        """Representation of a field."""
        return "%s = %s" % (self.name, self.value)

    def __len__(self):
        """Return the length of this field, in bits."""
        return self.SIZE_TABLE[self.STRUCT_FORMAT]

    def assign_data(self, data, start_bit):
        """Set the field's value given data."""
        self.value = self.extract_value(data, start_bit)

    def extract_value(self, data, start_bit):
        """Extract a value for this field out of given data."""
        if data is None:
            return self.DEFAULT_VALUE

        struct_format = "!%s" % self.STRUCT_FORMAT
        first_byte = start_bit / 8
        last_byte = first_byte + (len(self) / 8)

        return struct.unpack(struct_format, data[first_byte:last_byte])[0]


class Bit(Field):
    """A single bit...extracted from a byte."""

    STRUCT_FORMAT = "B"
    DEFAULT_VALUE = 0

    def extract_value(self, data, start_bit):
        """Extract a value for this field out of given data."""
        value = Field.extract_value(self, data, start_bit)
        return (value >> (start_bit % 8)) & 1


class UInt8(Field):
    """An unsigned 8-bit integer."""
    STRUCT_FORMAT = "B"
    DEFAULT_VALUE = 0


class UInt16(Field):
    """An unsigned 16-bit integer."""
    STRUCT_FORMAT = "H"
    DEFAULT_VALUE = 0


class FieldCollection(Field):
    """Collection of one or more `Field` and/or `FieldCollection` objects."""

    _fields = []

    def __init__(self, name=None, data=None):
        """Initialize a field collection."""
        Field.__init__(self, name, data)
        self._fields = copy.deepcopy(self.__class__._fields)

    def __repr__(self):
        """Return a good representation of this collection."""
        return pprint.pformat(filter(lambda f: f.name, self._fields))

    def __len__(self):
        """Calculate the length of this collection."""
        length = 0
        for field in self._fields:
            length += len(field)
        return length

    def assign_data(self, data, start_bit=0):
        """Assign the given data to this collection's fields."""
        for field in self._fields:
            field.assign_data(data, start_bit)
            start_bit += len(field)
        self.value = self

    def extract_value(self, data, start_bit):
        """Return ourself, because collections don't have values...persay."""
        return self

    def __getattribute__(self, name):
        """Overload __getattribute__ to provide easy access to fields."""
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            pass

        start_bit = 0
        for field in self._fields:
            if field.name == name:
                return field.value
            start_bit += len(field)

        raise AttributeError(name)

    def set_data(self, data):
        """Apply the given data to this collection's fields."""



class RadiotapFlags(FieldCollection):

    _fields = [
        Bit("tsft"),
        Bit("flags"),
        Bit("rate"),
        Bit("channel"),
        Bit("fhss"),
        Bit("dbm_antsignal"),
        Bit("dbm_antnoise"),
        Bit("lock_quality"),
        Bit("tx_attenuation"),
        Bit("db_tx_attenuation"),
        Bit("dbm_tx_power"),
        Bit("antenna"),
        Bit("db_antsignal"),
        Bit("db_antnoise"),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit(None),
        Bit("ext"),
   ]


class RadiotapFrame(FieldCollection):

    _fields = [
        UInt8("version"),
        UInt8("padding"),
        UInt16("length"),
        RadiotapFlags("fields"),
    ]


radiotap_frame = RadiotapFrame(data=TEST_PACKET)
print radiotap_frame.length
print radiotap_frame
