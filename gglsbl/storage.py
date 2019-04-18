#!/usr/bin/env python

import os
import hashlib
import contextlib
import sqlite3
import logging

from gglsbl.utils import to_hex
from .storageSqlite import SqliteStorage
from .storageMySQL import MySQLStorage

log = logging.getLogger('gglsbl')
log.addHandler(logging.NullHandler())

class ThreatList(object):
    """Represents threat list name."""

    def __init__(self, threat_type, platform_type, threat_entry_type):
        """Constructor."""
        self.threat_type = threat_type
        self.platform_type = platform_type
        self.threat_entry_type = threat_entry_type

    @classmethod
    def from_api_entry(cls, entry):
        return cls(entry['threatType'], entry['platformType'], entry['threatEntryType'])

    def as_tuple(self):
        return (self.threat_type, self.platform_type, self.threat_entry_type)

    def __repr__(self):
        """String representation of object"""
        return '/'.join(self.as_tuple())

class HashPrefixList(object):
    """Wrapper object for threat list data."""

    def __init__(self, prefix_size, raw_hashes):
        """Constructor.

        :param prefix_size: size of hash prefix in bytes (typically 4, sometimes 6)
        :param raw_hashes: string consisting of concatenated hash prefixes.
        """
        self.prefix_size = prefix_size
        self.raw_hashes = raw_hashes

    def __len__(self):
        """Number of individual hash prefixes in the list."""
        return int(len(self.raw_hashes) / self.prefix_size)

    def __iter__(self):
        """Iterate through concatenated raw hashes."""
        n = self.prefix_size
        return (self.raw_hashes[i:i + n] for i in range(0, len(self.raw_hashes), n))

