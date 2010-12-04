"""
yapcap.frames.layer2
"""

import BitPacket

import yapcap.util as util
import yapcap.util.constants as constants

from .base import Frame
from .layer3 import IPv4_Frame

class IEEE_8023_Frame(Frame):
    """
    IEEE_8023_Frame
    """

    @staticmethod
    def decode(pkt, data):
        """
        Decode data into pkt. Each time add_field is called, data is consumed.
        Be sure to return any unused data.
        """
        pkt.protocols.append("Ethernet")
        data = pkt.get_MAC("dst_mac")
        data = pkt.get_MAC((data, "src_mac",   48, util.MAC_Format)
        data = pkt.add_field(data, "ethertype", 16)

        if pkt["ethertype"] == constants.ETHERTYPE_IPv4:
            return IPv4_Frame.decode(pkt, data)

        return data


class IEEE_802_11_Radio_Frame(Frame):
    """
    IEEE_802_11_Radio_Frame
    """

    @staticmethod
    def decode(pkt, data):
        """
        Decode data into pkt. Each time add_field is called, data is consumed.
        Be sure to return any unused data.
        """
        data = pkt.add_custom_field(data, BitPacket.UInt8LE("radiotap_version"))
        data = pkt.add_custom_field(data, BitPacket.UInt8LE("radiotap_padding"))
        data = pkt.add_custom_field(data, BitPacket.UInt16LE("radiotap_length"))
        data = pkt.add_custom_field(data, BitPacket.UInt32LE("radiotap_fields"))

        data = pkt.add_field(data, "radiotap_flag_tsft", 1)
        data = pkt.add_field(data, "radiotap_flag_flags", 1)
        data = pkt.add_field(data, "radiotap_flag_rate", 1)
        data = pkt.add_field(data, "radiotap_flag_channel", 1)
        data = pkt.add_field(data, "radiotap_flag_fhss", 1)
        data = pkt.add_field(data, "radiotap_flag_antenna_signal", 1)
        data = pkt.add_field(data, "radiotap_flag_antenna_noise", 1)
        data = pkt.add_field(data, "radiotap_flag_lock_quality", 1)
        data = pkt.add_field(data, "radiotap_flag_tx_attenuation", 1)
        data = pkt.add_field(data, "radiotap_flag_dB_tx_attenuation", 1)
        data = pkt.add_field(data, "radiotap_flag_dBm_tx_power", 1)
        data = pkt.add_field(data, "radiotap_flag_antenna", 1)
        data = pkt.add_field(data, "radiotap_flag_dB_antenna_signal", 1)
        data = pkt.add_field(data, "radiotap_flag_dB_antenna_noise", 1)
        data = pkt.add_field(data, "radiotap_flag_rx_flags", 1)

        data = pkt.add_field(data, "radiotap_unknown1", 1)
        data = pkt.add_field(data, "radiotap_unknown2", 16)

        fn = IEEE_802_11_Radio_Frame.flag_conditional
        data = fn(data, pkt, "radiotap_flag_tsft", BitPacket.UInt64LE("radiotap_tsft"))
        data = fn(data, pkt, "radiotap_flag_flags", BitPacket.UInt8LE("radiotap_flags"))
        data = fn(data, pkt, "radiotap_flag_rate", BitPacket.UInt8LE("radiotap_rate"))
        data = fn(data, pkt, "radiotap_flag_channel", BitPacket.UInt16LE("radiotap_channel_frequency"))
        data = fn(data, pkt, "radiotap_flag_channel", BitPacket.UInt16LE("radiotap_channel_flags"))
        data = fn(data, pkt, "radiotap_flag_fhss", BitPacket.UInt8LE("radiotap_fhss_hop_set"))
        data = fn(data, pkt, "radiotap_flag_fhss", BitPacket.UInt8LE("radiotap_fhss_hop_pattern"))
        data = fn(data, pkt, "radiotap_flag_antenna_signal", BitPacket.UInt8LE("radiotap_antenna_signal"))
        data = fn(data, pkt, "radiotap_flag_antenna_noise", BitPacket.UInt8LE("radiotap_antenna_noise"))
        data = fn(data, pkt, "radiotap_flag_lock_quality", BitPacket.UInt16LE("radiotap_lock_quality"))
        data = fn(data, pkt, "radiotap_flag_tx_attenuation", BitPacket.UInt16LE("radiotap_tx_attenuation"))
        data = fn(data, pkt, "radiotap_flag_dB_tx_attenuation", BitPacket.UInt16LE("radiotap_dB_tx_attenuation"))
        data = fn(data, pkt, "radiotap_flag_dBm_tx_power", BitPacket.Int8LE("radiotap_dBm_tx_power"))
        data = fn(data, pkt, "radiotap_flag_antenna", BitPacket.UInt8LE("radiotap_antenna"))
        data = fn(data, pkt, "radiotap_flag_dB_antenna_signal", BitPacket.UInt8LE("radiotap_dB_antenna_signal"))
        data = fn(data, pkt, "radiotap_flag_dB_antenna_noise", BitPacket.UInt8LE("radiotap_dB_antenna_noise"))
        data = fn(data, pkt, "radiotap_flag_rx_flags", BitPacket.UInt16LE("radiotap_rx_flags"))

        return IEEE_802_11.decode(pkt, data)

    @staticmethod
    def flag_conditional(data, pkt, flag_field, data_field):
        """
        @param data: Data to be loaded if field exists
        @param pkt: Packet to check for the flag field
        @param flag_field: field to check in pkt
        @param data_field: field to insert into the pkt
        """
        if pkt[flag_field] == 1:
            return pkt.add_custom_field(data, data_field)
        else:
            return data


class IEEE_802_11(Frame):
    """
    IEEE_802_11
    """

    @staticmethod
    def decode(pkt, data):
        """
        Decode data into pkt. Each time add_field is called, data is consumed.
        Be sure to return any unused data.
        """
        data = pkt.add_field(data, "802.11_version", 2)
        data = pkt.add_field(data, "802.11_type", 2)
        data = pkt.add_field(data, "802.11_subtype", 4)
        data = pkt.add_field(data, "802.11_flag_to_ds", 1)
        data = pkt.add_field(data, "802.11_flag_from_ds", 1)
        data = pkt.add_field(data, "802.11_flag_more_fragments", 1)
        data = pkt.add_field(data, "802.11_flag_retry", 1)
        data = pkt.add_field(data, "802.11_flag_power_mgmt", 1)
        data = pkt.add_field(data, "802.11_flag_more_data", 1)
        data = pkt.add_field(data, "802.11_flag_wep", 1)
        data = pkt.add_field(data, "802.11_flag_order", 1)
        data = pkt.add_field(data, "802.11_duration_id", 16)
        data = pkt.add_field(data, "802.11_mac1", 48)

        print pkt
    
        return data
 

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


L2_Factory.register(IEEE_8023_Frame, 
    [
        constants.DLT_EN10MB, 
        constants.DLT_IEEE802_11, 
        constants.DLT_IEEE802_11_RADIO
    ]
)

L2_Factory.register(IEEE_802_11_Radio_Frame, 
    [
        constants.DLT_IEEE802_11_RADIO
    ]
)
