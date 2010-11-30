"""
layer2.py
"""

from BitPacket import BitStructure, BitField

from yapcap.frames import Frame
from yapcap.constants import DLT_EN10MB, DLT_IEEE802_11, DLT_IEEE802_11_RADIO

class L2_Factory(object):
    """
    L2_Factory
    """

    _dispatch = {}    

    @staticmethod
    def register(cls, linktypes):
        """
        Register the given linktypes with the given class.
        """
        for linktype in linktypes:
            L2_Factory._dispatch[linktype] = cls

    @classmethod
    def from_linktype(cls, linktype):
        """
        Return a class based on the BPF integer passed back to us from libpcap.
        """
        return cls._dispatch.get(linktype)
        

class IEEE_8023_Frame(Frame):
    """
    IEEE_8023_Frame
    """

    def __init__(self, data):
        Frame.__init__(self, data)

        self.structure = BitStructure(self.__class__.__name__)
        self.add_field("dst_mac",   48)
        self.add_field("src_mac",   48)
        self.add_field("ethertype", 16)

        self.check()
        self.claim_data()

        self.structure.set_bytes(self.data)


class IEEE_802_11_Radio_Frame(Frame):
    """
    IEEE_802_11_Radio_Frame
    """

    _flag_fields = [
        ("tsft"              , 64),
        ("flags"             , 8),
        ("rate"              , 8),
        ("channel"           , 32),
        ("fhss"              , 16),
        ("dbm_antsignal"     , 8),
        ("dbm_antnoise"      , 8),
        ("lock_quality"      , 16),
        ("tx_attenuation"    , 16),
        ("db_tx_attenuation" , 16),
        ("dbm_tx_power"      , 8),
        ("antenna"           , 8),
        ("db_antsignal"      , 8),
        ("db_antnoise"       , 8),
        ("rx_flags"          , 16),
        ("tx_flags"          , 16),
        ("rts_retires"       , 8),
        ("data_retires"      , 8),
        ("ext"               , 8),
    ]

    def __init__(self, data):
        Frame.__init__(self, data)

        self.structure = BitStructure(self.__class__.__name__)
        self.add_field("header_revision", 8)
        self.add_field("header_padding", 8)
        self.add_field("header_length", 16)
        self.add_field("has_tsft", 1)
        self.add_field("has_flags",           1)
        self.add_field("has_rate",            1)
        self.add_field("has_channel",         1)
        self.add_field("has_fhss",            1)
        self.add_field("has_dbm_antsignal",   1)
        self.add_field("has_dbm_antnoise",    1)
        self.add_field("has_lock_quality",    1)
        self.add_field("has_tx_attenuation",  1)
        self.add_field("has_db_tx_attenuation", 1)
        self.add_field("has_dbm_tx_power",    1)
        self.add_field("has_antenna",         1)
        self.add_field("has_db_antsignal",    1)
        self.add_field("has_db_antnoise",     1)
        self.add_field("has_rx_flags",        1)
        self.add_field("has_tx_flags",        1)
        self.add_field("has_rts_retires",     1)
        self.add_field("has_data_retires",    1)
        self.add_field("has_ext",             1)
    
        self.check()

        self.structure.set_bytes(data[0:8])
        
        for (name, size) in self._flag_fields:
            if self.structure[name]:
                self.add_field("%s_data" % name, size)

        self.claim_data()

        self.structure.set_bytes(self.data)


L2_Factory.register(IEEE_8023_Frame, [DLT_EN10MB, DLT_IEEE802_11, DLT_IEEE802_11_RADIO])
L2_Factory.register(IEEE_802_11_Radio_Frame, [DLT_IEEE802_11_RADIO])
