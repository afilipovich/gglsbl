#!/usr/bin/env python

__all__ = [
    'SafeBrowsingList'
]

from .client import SafeBrowsingList

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
