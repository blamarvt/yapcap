"""
yapcap.util.formats
"""

import socket
import struct

from BitPacket import Value

from .constants import IPv4_PROTOCOLS

class IPv4_Format(object):
    """
    IPv4_Format
    """

    @staticmethod
    def output(field):
        """
        Output the given raw value as something more readable.
        """
        return socket.inet_ntoa(struct.pack("!L", field.hex_value()))


class LE_Int_u16_Format(object):
    """
    LE_Int_u16_Format
    """

    @staticmethod
    def output(field):
        """
        Output this field as an integer.
        """
        return Value(field.name(), "<H", field.bytes())


class IPv4_Protocol_Format(object):
    """
    IPv4_Protocol_Format
    """
    
    @staticmethod
    def output(field):
        """
        Output string depending on the protocol.
        """
        for item in dir(socket):
            if item.startswith("IPPROTO") and getattr(socket, item) == field.hex_value():
                return item

        return "unknown"

class Hex_Format(object):
    """
    Hex_Format
    """
    
    @staticmethod
    def output(field):
        """
        Output in hex format.
        """
        return field.str_hex_value()


class MAC_Format(object):
    """
    MAC_Format
    """
    
    @staticmethod
    def output(field):
        """
        Output the given MAC in a readable format.
        """
        hs = str(field.str_hex_value())[2:]
        return "%s:%s:%s:%s:%s:%s" % (hs[0:2], hs[2:4], hs[4:6], hs[6:8], hs[8:10], hs[10:12])
