#!/usr/bin/python
import sys
import pprint
import cyapcap
import yapcap.util
import yapcap.frames

def main(device):
    linktype = cyapcap.check(device)
    base_cls = yapcap.frames.L2_Factory.from_linktype(linktype)

    def process(summary, raw_packet):
        """
        Process each incoming packet.
        """
        info = {}
        packet = yapcap.util.YapcapPacket(base_cls)
        packet.decode(raw_packet)

        if 'Ethernet' in packet.protocols:
            info['src_mac'] = packet.src_mac
            info['dst_mac'] = packet.dst_mac

        if 'IP' in packet.protocols:
            info['src_ip'] = packet.src_ip
            info['dst_ip'] = packet.dst_ip
            info['ip_protocol'] = packet.ip_protocol

        if 'TCP' in packet.protocols:
            info['src_port'] = packet["src_port"]
            info['dst_port'] = packet["dst_port"]
            info["tcp_options"] = packet.tcp_options
            
        if 'HTTP' in packet.protocols:
            if packet.http_type == "request":
                info['http_method']  = packet.http_method
                info['http_host']    = packet.http_host
                info['http_cookie']  = packet.http_cookie
                info['http_content'] = packet.http_content

                pprint.pprint(info)

    cyapcap.capture(device, process)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "usage: %prog interface"
        sys.exit(1)
    else:
        interface = sys.argv[1]
        main(interface)
