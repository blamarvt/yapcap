"""
yapcap.dispatcher
"""

from impacket import ImpactDecoder

class DecoderDispatcher(object):
    """
    DecoderDispatcher
    """
    
    _map = {
        1   : ImpactDecoder.EthDecoder(),
        127 : ImpactDecoder.RadioTapDecoder()
    }

    @classmethod
    def get(cls, linktype):
        """
        Retrieve a decoder.
        """
        try:
            return cls._map[linktype]
        except KeyError:
            raise ValueError("Unsupported linktype (%d)" % linktype)
