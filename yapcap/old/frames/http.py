"""
yapcap.frames.http
"""

import yapcap.util as util

from .base import Frame

class HTTP_Packet(Frame):
    """
    HTTP_Packet
    """

    _response_protocols = [
        'HTTP/1.0', 'HTTP/1.1'
    ]    

    _request_keywords = [
        'GET', 'POST', 'PUT', 'OPTIONS', 'HEAD'
    ]

    @staticmethod
    def decode(pkt, data):
        pkt.protocols.append("HTTP")
        
        lines = data.split("\n")
        first = lines[0].split(" ")
        
        if first[0] in HTTP_Packet._response_protocols:
            pkt.http_type = "response"
        elif first[0] in HTTP_Packet._request_keywords:
            pkt.http_type = "request"
            pkt.http_method = first[0]
            pkt.http_location = first[1]

        for line in lines:
            if line == '\r':
                break

            header = line.split(":", 1)
            if len(header) == 2:
                key = header[0].replace("-", "_").lower()
                value = header[1].strip('\r')
                setattr(pkt, "http_%s" % key, value)
        
        return data
