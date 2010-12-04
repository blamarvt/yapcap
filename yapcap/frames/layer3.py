"""
yapcap.frames.layer3
"""

import socket

import yapcap.util as util

from .base import Frame
from .layer4 import TCP_Frame

class IPv4_Frame(Frame):
    """
    IPv4_Frame
    """

    @staticmethod
    def decode(pkt, data):
        pkt.protocols.append("IP")
        data = pkt.add_field(data, "ip_version",   4)
        data = pkt.add_field(data, "ip_hlen",      4)
        data = pkt.add_field(data, "ip_codepoint", 6)
        data = pkt.add_field(data, "ip_unused",    2)
        data = pkt.add_field(data, "ip_total_len", 16)
        data = pkt.add_field(data, "ip_ident",     16)
        data = pkt.add_field(data, "ip_reserved",  1)
        data = pkt.add_field(data, "ip_no_frag",   1)
        data = pkt.add_field(data, "ip_more_frag", 1)
        data = pkt.add_field(data, "ip_offset",    13)
        data = pkt.add_field(data, "ip_ttl",       8)
        data = pkt.add_field(data, "ip_protocol",  8, util.IPv4_Protocol_Format)
        data = pkt.add_field(data, "ip_hchksum",   16)
        data = pkt.add_field(data, "src_ip",       32, util.IPv4_Format)
        data = pkt.add_field(data, "dst_ip",       32, util.IPv4_Format)

        if pkt["ip_protocol"] is socket.IPPROTO_TCP:
            return TCP_Frame.decode(pkt, data)

        return data
