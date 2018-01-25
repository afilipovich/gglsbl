#!/usr/bin/env python

from setuptools import setup
import versioneer

setup(name='gglsbl',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="Client library for Google Safe Browsing Update API v4",
    classifiers=[
        "Operating System :: POSIX",
        "Environment :: Console",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords='google safe browsing api client',
    author='Aleh Filipovich',
    author_email='aleh@vaolix.com',
    url='https://github.com/afilipovich/gglsbl',
    license='Apache2',
    packages=['gglsbl'],
    install_requires=['google-api-python-client>=1.4.2,<2'],
    scripts=['bin/gglsbl_client.py'],
)
