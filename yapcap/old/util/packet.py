"""
yapcap.util.packet
"""

import struct

from BitPacket import BitStructure, BitField, Value

class YapcapPacket(BitStructure):
    """
    Yapcap Packet Class
    """

    _formats = {}

    def __init__(self, data, base_cls):
        """
        Initialize our packet. Start point class required.
        """
        BitStructure.__init__(self, self.__class__.__name__)
        self.data = data
        self.base_cls = base_cls
        self.protocols = []

    def decode(self):
        """
        Decode the frame from network data.
        """
        self.base_cls.decode(self)

    def add_field(self, data, name, bits, format_cls=None, force_assign=False):
        """
        @param name: The name of the field
        @param bits: The number of bits
        @param format_cls: The format class for the field
        """
        if format_cls:
            self._formats[name] = format_cls

        field = BitField(name, bits)
        self.append(field)

        num_bits = 1
        if num_bits % 8 == 0 or force_assign:
            self.set_bytes(data[0:self.size()])
            data = data[self.size():]

        return data

    def add_custom_field(self, data, field, format_cls=None, force_assign=False):
        """
        @param data: Data to be assigned to the field
        @param field_cls: The bitpacket instance, like a BitField
        @param format_cls: The format class for the field
        """
        if format_cls:
            self._formats[name] = format_cls

        field.set_bytes(data[0:field.size()])
        data = data[field.size():]

        self.append(field)

        return data

    def has_field(self, key):
        """
        Does the BitStructure have a fields named <key>?
        """
        try:
            self[key]
            return True
        except KeyError:
            return False

    def get_field(self, key):
        """
        Retrieve the field based on the key.
        """
        for field in self.fields():
            if field.name() == key:
                return field

    def __getattr__(self, key):
        """
        Get attribute provides BitStructure items formatted
        correctly.
        """
        if key in self._formats and self.has_field(key):
            return self._formats[key].output(self.get_field(key))
        elif self.has_field(key):
            return self[key]
        else:
            return None
