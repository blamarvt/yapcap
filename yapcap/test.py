#!/usr/bin/python
import binascii
import cYapcap
import struct

class NetworkFrame(object):
    def __init__(self, data):
        self.data = data

    def bytes(self, num_bytes, format=None):
        data = self.data[0:num_bytes]
        self.data = self.data[num_bytes:]

        print "Processing %d byte request." % num_bytes

        if format is None:
            return struct.unpack("!%ds" % num_bytes, data)[0]
        elif format == "mac":
            return struct.unpack("!%ds" % num_bytes, data)[0].encode('hex')

    def bits(self, num_bits):
        pass


class EthernetIIFrame(NetworkFrame):
    def __init__(self, data):
        NetworkFrame.__init__(self, data)

        # 802.3 Fields
        self.dst_mac = self.bytes(6, format="mac")
        self.src_mac = self.bytes(6, format="mac")
        self.type    = self.bytes(2)

        print self.dst_mac, len(self.dst_mac)
    

class IPv4Frame(NetworkFrame):
    def __init__(self, data):
        NetworkFrame.__init__(self, data)

        # Ethernet Fields
        self.version   = self.bits(4)
        self.hlen      = self.bits(4)
        self.codepoint = self.bits(6)
        _              = self.bits(2)
        self.total_len = self.bytes(2)
        self.ident     = self.bytes(2)
        self.reserved  = self.bits(1)
        self.no_frag   = self.bits(1)
        self.more_frag = self.bits(1)
        self.offset    = self.bits(13)
        self.ttl       = self.bytes(1)
        self.protocol  = self.bytes(1)
        self.hchksum   = self.bytes(2)
        self.src_ip    = self.bytes(4)
        self.dst_ip    = self.bytes(4)
"""
ethernet_frame = Prototype()
ethernet_frame.add_string("dst_mac", 6)
ethernet_frame.add_string("src_mac", 6)
ethernet_frame.add_string("type", 2)
EthernetFrame = ethernet_frame.klass('EthernetFrame')
del ethernet_frame

# IP Protocol Frame (http://www.networksorcery.com/enp/protocol/ip.htm)
ip_frame = Prototype()
ip_frame.add_uint32("version")
IpFrame = ip_frame.klass('IpFrame')
del ip_frame
"""

def callback(summary, packet):
    pkt = struct.unpack("%ds" % len(packet), packet)[0]
    bpkt = "".join([str(bin(ord(s)))[2:].rjust(8, '0') for s in pkt])
    print bpkt

cYapcap.capture("wlan0", callback)
