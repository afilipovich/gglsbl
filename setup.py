#!/usr/bin/env python2.7

from setuptools import setup

import sys, os

__version__ = '0.6'

setup(name='gglsbl',
    version=__version__,
    description="Client library for Google Safe Browsing API",
    classifiers=[
        "Operating System :: POSIX",
        "Environment :: Console",
        "Programming Language :: Python",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords='safe browsing api client',
    author='Aleh Filipovich',
    author_email='aleh@vaolix.com',
    url='https://github.com/afilipovich/gglsbl',
    license='Apache2',
    packages=['gglsbl'],
    install_requires=['argparse', 'pysqlite', 'protobuf'],
    scripts=['bin/gglsbl_client.py'],
)
