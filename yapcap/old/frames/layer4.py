"""
yapcap.frames.layer4
"""

import yapcap.util as util

from .base import Frame
from .http import HTTP_Packet

class TCP_Frame(Frame):
    """
    TCP_Frame
    """

    @staticmethod
    def decode(pkt, data):
        pkt.protocols.append("TCP")
        data = pkt.add_field(data, "src_port",        16)
        data = pkt.add_field(data, "dst_port",        16)
        data = pkt.add_field(data, "tcp_seq",         32)
        data = pkt.add_field(data, "tcp_ack_num",     32)
        data = pkt.add_field(data, "tcp_offset",       4)
        data = pkt.add_field(data, "tcp_reserved",     3)
        data = pkt.add_field(data, "tcp_ns",           1)
        data = pkt.add_field(data, "tcp_cwr",          1)
        data = pkt.add_field(data, "tcp_ece",          1)
        data = pkt.add_field(data, "tcp_urgent",       1)
        data = pkt.add_field(data, "tcp_ack",          1)
        data = pkt.add_field(data, "tcp_psh",          1)
        data = pkt.add_field(data, "tcp_rst",          1)
        data = pkt.add_field(data, "tcp_syn",          1)
        data = pkt.add_field(data, "tcp_fin",          1)
        data = pkt.add_field(data, "tcp_window",      16)
        data = pkt.add_field(data, "tcp_chksum",      16)
        data = pkt.add_field(data, "tcp_urgent_ptr",  16)

        # TODO: Parse Options
        data = pkt.add_field(data, "tcp_options", (pkt["tcp_offset"] - 5) * 32, util.Hex_Format)

        if pkt["src_port"] == 80 or pkt["dst_port"] == 80:
            return HTTP_Packet.decode(pkt, data)

        return data
