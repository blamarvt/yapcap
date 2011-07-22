"""
yapcap.frames.base
"""

class Frame(object):
    """
    Base Frame Class
    """

    @staticmethod
    def decode(pkt, data):
        """
        Decode the frame from network data.
        """
        raise NotImplementedError()
