"""
layer3.py
"""

from BitPacket import BitStructure, BitField

from yapcap.frames import Frame

class IPv4_Frame(Frame):
    """
    IPv4_Frame
    """

    def __init__(self, data):
        Frame.__init__(self, data)

        self.structure = BitStructure("IPv4_Frame")
        self.structure.append(BitField("version",   4))
        self.structure.append(BitField("hlen",      4))
        self.structure.append(BitField("codepoint", 6))
        self.structure.append(BitField("unused",    2))
        self.structure.append(BitField("total_len", 16))
        self.structure.append(BitField("ident",     16))
        self.structure.append(BitField("reserved",  1))
        self.structure.append(BitField("no_frag",   1))
        self.structure.append(BitField("more_frag", 1))
        self.structure.append(BitField("offset",    13))
        self.structure.append(BitField("ttl",       8))
        self.structure.append(BitField("protocol",  8))
        self.structure.append(BitField("hchksum",   16))
        self.structure.append(BitField("src_ip",    32))
        self.structure.append(BitField("dst_ip",    32))

        self.check()
        self.claim_data()

        self.structure.set_bytes(self.data)

