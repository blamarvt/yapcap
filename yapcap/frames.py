"""
frames.py
"""

from BitPacket import BitStructure, BitField

class Frame(object):
    def __init__(self, data):
        self.data = data

    def check(self):
        """
        Check data vs. data structure to make sure that
        it's an appropriate size.
        """
        d_size = len(self.data)
        my_size = self.structure.size()

        if d_size < my_size:
            raise ValueError("%s is %d bytes, got %d bytes." % (my_size, d_size))

    def size(self):
        """
        Return the size of the structure, or error if we 
        don't have a structure.
        """
        return self.structure.size()

    def claim_data(self):
        """
        Set data to be only what we need and assign the rest to 
        the frame "content".
        """
        my_data = self.data[0:self.size()]
        self.content = self.data[self.size():]
        self.data = my_data

    def __getattr__(self, key):
        """
        Provide the ability to access structure elements
        from the Frame level.
        """
        try:
            return self.__dict__[key]
        except KeyError as ex:
            if key in self.structure.keys():
                return self.output(key)
            else:
                raise

    def __setattr__(self, key, value):
        """
        Provide the ability to edit structure elements
        from the Frame level.
        """
        try:
            dict.__setattr__(self, key, value)
        except AttributeError as ex:
            if key in self.structure.keys():
                self.input(key, value)
            else:
                raise

    def input(self, key, value):
        """
        Handle input heading towards a BitField.
        """
        self.structure[key] = value

    def output(self, key):
        """
        Handle output from a BitField.
        """
        return self.structure[key]

class IEEE_8023_Frame(Frame):
    def __init__(self, data):
        Frame.__init__(self, data)

        self.structure = BitStructure("IEEE_8023_Frame")
        self.structure.append(BitField("dst_mac",   48))
        self.structure.append(BitField("src_mac",   48))
        self.structure.append(BitField("ethertype", 16))

        self.check()
        self.claim_data()

        self.structure.set_bytes(self.data)

#    ethertype = property(fget=lambda self: self.structure["ethertype"])


class IPv4_Frame(Frame):
    def __init__(self, data):
        Frame.__init__(self, data)

        self.structure = BitStructure("IPv4_Frame")
        self.structure.append(BitField("version",   4))
        self.structure.append(BitField("hlen",      4))
        self.structure.append(BitField("codepoint", 6))
        self.structure.append(BitField("unused",    2))
        self.structure.append(BitField("total_len", 16))
        self.structure.append(BitField("ident",     16))
        self.structure.append(BitField("reserved",  1))
        self.structure.append(BitField("no_frag",   1))
        self.structure.append(BitField("more_frag", 1))
        self.structure.append(BitField("offset",    13))
        self.structure.append(BitField("ttl",       8))
        self.structure.append(BitField("protocol",  8))
        self.structure.append(BitField("hchksum",   16))
        self.structure.append(BitField("src_ip",    32))
        self.structure.append(BitField("dst_ip",    32))

        self.check()
        self.claim_data()

        self.structure.set_bytes(self.data)

