#!/usr/bin/python
import sys
import pprint
import yapcap
import cyapcap

def main(device):
    linktype = cyapcap.check(device)
    decoder = yapcap.load_decoder(linktype)

    def process(summary, raw_packet):
        """
        Process each incoming packet.
        """
        info = {}
        packet = decoder.decode(raw_packet)

        if 'Ethernet' in packet.protocols:
            info['src_mac'] = packet.src_mac
            info['dst_mac'] = packet.dst_mac

        if 'IP' in packet.protocols:
            info['src_ip'] = packet.src_ip
            info['dst_ip'] = packet.dst_ip
            
        if 'HTTP' in packet.protocols:
            info['http_method'] = packet.http_method
            info['http_host'] = packet.http_host
            info['http_cookie'] = packet.http_cookie
            info['http_content'] = packet.http_content

        if packet.from_wireless:
            info['ssid'] = packet.ssid

        pprint.pprint(info)

    cyapcap.capture(device, process)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "usage: %prog interface"
        sys.exit(1)
    else:
        interface = sys.argv[1]
        main(interface)
