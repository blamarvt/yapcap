#!/usr/bin/python

import setuptools
import distutils.core

cYapcap = distutils.core.Extension(
    'cyapcap',
    sources=['cyapcap/yapcap.c'],
    libraries=['pcap'],
)

distutils.core.setup(
    name='python-yapcap',
    version='0.2.1',
    description='Yet Another Packet Captor',
    ext_modules=[cYapcap],
    install_requires=[
        'impacket',
        'BitPacket',
        'BitVector',
    ],
    packages=[
        'cyapcap',
        'yapcap',
        'yapcap.util',
        'yapcap.frames',
    ],
)
