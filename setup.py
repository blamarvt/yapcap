#!/usr/bin/python

import setuptools
from distutils.core import setup, Extension

cYapcap = Extension('cYapcap', 
    sources   = ['yapcap.c'],
    libraries = ['pcap'],
)

setup (
    name             = 'python-yapcap',
    version          = '0.1',
    description      = 'Yet Another Packet Captor',
    ext_modules      = [cYapcap],
    install_requires = ['packet', 'BitVector'],
)
