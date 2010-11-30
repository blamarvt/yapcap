#!/usr/bin/python

import setuptools
from distutils.core import setup, Extension

cYapcap = Extension('cyapcap', 
    sources   = ['cyapcap/yapcap.c'],
    libraries = ['pcap'],
)

setup (
    name             = 'python-yapcap',
    version          = '0.2.1',
    description      = 'Yet Another Packet Captor',
    ext_modules      = [cYapcap],
    install_requires = ['impacket'],
    packages         = ['cyapcap', 'yapcap']
)
