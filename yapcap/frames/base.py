"""
base.py
"""

from BitPacket import BitStructure, BitField

class Frame(object):
    """
    Frame
    """

    def __init__(self, data):
        self.data = data
        self.layers = []
        self.fields = []
        self.structure = BitStructure(self.__class__.__name__)

    def add_field(self, name, bits, format_cls=None):
        """
        @param name: The name of the field
        @param bits: The number of bits
        @param format_cls: The format class for the field
        """
        self.structure.append(BitField(name, bits))

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

