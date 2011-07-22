#!/usr/bin/python
import pprint
import sys

import cyapcap


def main(device):
    print device
    print cyapcap.check(device)
    cyapcap.capture(device, lambda summary, packet: pprint.pprint(packet))


if __name__ == "__main__":
    main(sys.argv[1])
