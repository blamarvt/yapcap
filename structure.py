"""
create classes to (un)pack packets to/from objects with named fields

The packet module is a front-end to the struct module.  It allows the
user to define a packet format, and to create a Python class to represent
those packets with named attributes for each packet field::

    # demo: make an IP packet packer/unpacker

    # IP Prototype
    ipp = Prototype()
    ipp.add_uint8('vhl')
    ipp.add_uint8('tos')
    ipp.add_uint16('len')
    ipp.add_uint16('id')
    ipp.add_uint16('off')
    ipp.add_uint8('ttl')
    ipp.add_uint8('p')
    ipp.add_uint16('sum')
    ipp.add_uint32('src')
    ipp.add_uint32('dst')
    IP = ipp.klass('IP', NETWORK)
    del ipp

    # ....

    # create an IP packet instance from bytes
    packet = IP(bytes)

    # create an empty packet
    packet = IP()

    # access fields
    print packet.len

    # pack fields into bytes
    bytes = packet.pack()
"""

__author__ = 'Phil Budne <phil@ultimate.com>'
__version__ = '0.4'
__revision__ = '$Id: packet.py,v 1.14 2010/04/04 01:04:15 phil Exp $'

#       Copyright (c) 2009 Philip Budne (phil@ultimate.com)
#       Licensed under the MIT licence: 
#       
#       Permission is hereby granted, free of charge, to any person
#       obtaining a copy of this software and associated documentation
#       files (the "Software"), to deal in the Software without
#       restriction, including without limitation the rights to use,
#       copy, modify, merge, publish, distribute, sublicense, and/or sell
#       copies of the Software, and to permit persons to whom the
#       Software is furnished to do so, subject to the following
#       conditions:
#       
#       The above copyright notice and this permission notice shall be
#       included in all copies or substantial portions of the Software.
#       
#       THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#       EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#       OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#       NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
#       HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
#       WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#       FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
#       OTHER DEALINGS IN THE SOFTWARE.

import struct
import sys

                                # ORDER         ALIGNMENT
NATIVEA = '@'                   # native        native
NATIVE = '='                    # native        standard
LITTLEENDIAN = '<'              # little        standard
BIGENDIAN = '>'                 # big           standard
NETWORK = '!'                   # network       standard

# IDEAS:
# pass "dump" format into "add" methods, keep in a dict

class Prototype(object):
    """
    Prototype objects are used to construct new packet type classes.

    After Prototype instantiation, add fields, with add_xxx() methods,
    then create a new class with the klass() method.
    """

    def __init__(self):
        self.fields = []
        self.format = ""
        self.len = 0

    def _add(self, name, format_string, format_len, formatter=None):
        """field-maker helper"""
        self.fields.append((name, formatter))
        self.format += format_string
        self.len += format_len

    def add_pad(self, flen=1):
        """add a pad field (ignored bytes)"""
        self.format += "%dx" % len
        self.len += flen

    def add_int8(self, name):
        """add a signed 8-bit integer (byte) field"""
        self._add(name, 'b', 1)

    def add_uint8(self, name):
        """add an unsigned 8-bit integer (byte) field"""
        self._add(name, 'B', 1)

    def add_int16(self, name):
        """add a signed 16-bit integer field"""
        self._add(name, 'h', 2)

    def add_uint16(self, name):
        """add an unsigned 16-bit integer field"""
        self._add(name, 'H', 2)

    def add_int32(self, name):
        """add a signed 32-bit integer field"""
        self._add(name, 'i', 4)

    def add_uint32(self, name):
        """add an unsigned 32-bit integer field"""
        self._add(name, 'I', 4)

    def add_string(self, name, flen):
        """add a fixed-length string (or sub-structre) field"""
        self._add(name, "%ds" % flen, flen)

    def klass(self, name, order=NETWORK):
        """
        Returns a new class for this packet type:
        `name' is the name for the class,
        `order' is one of:
                                        # ORDER         ALIGNMENT
        packet.NATIVEA = '@'            # native        native
        packet.NATIVE = '='             # native        standard
        packet.LITTLEENDIAN = '<'       # little        standard
        packet.BIGENDIAN = '>'          # big           standard
        packet.NETWORK = '!'            # network       standar

        The returned class' constructor takes a string to unpack,
        or None to construct an empty packet
        (all fields initialized to zeroes).

        Each class has a value attribute for each defined field,
        and a pack() method to pack up the current packet contents.
        """

        new = type(name, (Packet,), {
                '__doc__': "%s packet" % name,
                '_fields': self.fields,
                '_format': order + self.format,
                '_len': self.len })
        return new

class Packet(object):
    """base class for all packet classes"""

    # keep pylint quiet:
    _format = ''
    _len = 0
    _fields = []

    def __init__(self, data=None):
        if data is None:
            data = "\0" * self._len
        if len(data) > self._len:
            data = data[0:self._len]
        values = struct.unpack(self._format, data)
        for i in xrange(0, len(values)):
            setattr(self, self._fields[i][0], values[i])

    def __len__(self):
        return self._len

    def pack(self):
        """return packed string with packet contents"""
        values = [getattr(self, fld) for fld,_ in self._fields]
        return struct.pack(self._format, *values)

    def dump(self, out=sys.stdout, show_all=False):
        """dump field values to `out'"""
        for field,_ in self.__class__._fields:
            value = getattr(packet, field)
            if show_all or value != 0:
                out.write("%s: %x\n" % (field, value))

if __name__ == '__main__':
    # demo: make an IP packet packer/unpacker

    # IP Prototype
    ipp = Prototype()
    ipp.add_uint8('vhl')
    ipp.add_uint8('tos')
    ipp.add_uint16('len')
    ipp.add_uint16('id')
    ipp.add_uint16('off')
    ipp.add_uint8('ttl')
    ipp.add_uint8('p')
    ipp.add_uint16('sum')
    ipp.add_uint32('src')
    ipp.add_uint32('dst')
    IP = ipp.klass('IP', NETWORK)
    del ipp

    print IP
    print IP.__name__
    print IP.__doc__
    print IP._len
    print IP._format

    sample = struct.pack("20B",
                         0x45, 0x00, 0x00, 0x34,
                         0x43, 0x42, 0x40, 0x00,
                         0x40, 0x06, 0x30, 0xbd,
                         0xc0, 0xa8, 0x0f, 0x1c,
                         0x52, 0x5e, 0xa4, 0xa2)

    # load sample bytestring into an IP packet
    packet = IP(sample)
    print "packet len:", len(packet)

    # dump fields
    packet.dump()

    # repack, and check if same
    repacked = packet.pack()
    assert sample == repacked
