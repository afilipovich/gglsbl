#!/usr/bin/env python

__all__ = [
    'SafeBrowsingList'
]

from gglsbl.client import SafeBrowsingList

from gglsbl._version import get_versions
__version__ = get_versions()['version']
del get_versions
