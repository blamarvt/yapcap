#!/usr/bin/python
import sys

import cyapcap

from yapcap.frames import IEEE_8023_Frame, IPv4_Frame
from yapcap.constants import ETHERTYPE_IPv4

def process(summary, packet):
    """
    Current we can ensure that `capture` will only return items which are 
    compatible with the IEEE 802.3 frame, so we start there. From there,
    choices are currently limited to IPv4, but IPv6 support shouldn't be
    difficult.
    """
    layer2_frame = IEEE_8023_Frame(packet)
    
    if layer2_frame.ethertype == ETHERTYPE_IPv4:
        layer3_frame = IPv4_Frame(layer2_frame.content)
        print layer3_frame.structure
    else:
        print >>sys.stderr, "Encountered unknown type: %x" % layer2_frame.ethertype

cyapcap.capture("wlan0", process)
