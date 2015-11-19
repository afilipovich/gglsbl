#!/usr/bin/env python

import os
import sqlite3

import logging
log = logging.getLogger()
log.addHandler(logging.NullHandler())


class StorageBase(object):
    @staticmethod
    def compress_ranges(nums):
        """Compress consequtive ranges in sequence of numbers

        E.g. [1,2,3,4,7] -> '1-4,7'
        """
        if not nums:
            return None
        nums.sort()
        buf = []
        buf.append(nums[0])
        for i in xrange(1, len(nums)):
            if nums[i-1] == nums[i]:
                pass
            elif nums[i] - nums[i-1] == 1:
                if buf[-1] is not None:
                    buf.append(None)
            else:
                if buf[-1] is None:
                    buf.append(nums[i-1])
                buf.append(nums[i])
        if buf[-1] is None:
            buf.append(nums[-1])
        output = ','.join([str(i) for i in buf])
        output = output.replace(',None,', '-')
        return output

    @staticmethod
    def expand_ranges(list_of_ranges):
        """Do the opposite of compress_ranges()

        E.g. '1-4,7' -> [1,2,3,4,7]
        """
        nums = []
        for ranges in list_of_ranges:
            for r in ranges.strip().split(','):
                if type(r) is int:
                    nums.append(r)
                elif r.isdigit():
                    nums.append(int(r))
                else:
                    try:
                        r1, r2 = r.split('-')
                        r1 = int(r1)
                        r2 = int(r2) + 1
                        nums.extend(xrange(r1, r2))
                    except ValueError as e:
                        log.error('Failed to parse chunk range "%s"' % r)
                        raise
        return nums


class SqliteStorage(StorageBase):
    """Storage abstraction for local GSB cache"""
    def __init__(self, db_path):
        do_init_db = not os.path.isfile(db_path)
        log.info('Opening SQLite DB %s' % db_path)
        self.db = sqlite3.connect(db_path)
        self.dbc = self.db.cursor()
        if do_init_db:
            log.info('SQLite DB does not exist, initializing')
            self.init_db()
        self.dbc.execute('PRAGMA synchronous = 0')

    def init_db(self):
        self.dbc.execute(
        """CREATE TABLE chunk (
            chunk_number integer NOT NULL,
            timestamp timestamp DEFAULT current_timestamp,
            list_name character varying(127) NOT NULL,
            chunk_type TEXT CHECK( chunk_type IN ('add','sub')) NOT NULL,
            PRIMARY KEY (chunk_number, list_name, chunk_type)
            )"""
        )
        self.dbc.execute(
        """CREATE TABLE full_hash (
            value BLOB NOT NULL,
            list_name character varying(127) NOT NULL,
            downloaded_at timestamp DEFAULT current_timestamp,
            expires_at timestamp without time zone NOT NULL,
            PRIMARY KEY (value)
            )"""
        )

        self.dbc.execute(
        """CREATE TABLE hash_prefix (
            value BLOB NOT NULL,
            chunk_number integer NOT NULL,
            timestamp timestamp without time zone DEFAULT current_timestamp,
            list_name character varying(127) NOT NULL,
            chunk_type TEXT CHECK( chunk_type IN ('add','sub')) NOT NULL,
            full_hash_expires_at timestamp NOT NULL DEFAULT current_timestamp,
            PRIMARY KEY (value, chunk_number, list_name, chunk_type),
            FOREIGN KEY(chunk_number, list_name, chunk_type)
                REFERENCES chunk(chunk_number, list_name, chunk_type)
                ON DELETE CASCADE
            )"""
        )
        self.db.commit()

    def chunk_exists(self, chunk):
        "Check if given chunk records already exist in the database"
        q = 'SELECT COUNT(*) FROM chunk WHERE chunk_number=? AND \
            chunk_type=? AND list_name=?'
        self.dbc.execute(q, [chunk.chunk_number, chunk.chunk_type, chunk.list_name])
        if self.dbc.fetchall()[0][0] > 0:
            return True
        return False

    def store_chunk(self, chunk):
        "Store chunk in the database"
        log.debug('Storing %s chunk #%s for list name %s' % (chunk.chunk_type, chunk.chunk_number, chunk.list_name))
        self.insert_chunk(chunk)
        for hash_value in chunk.hashes:
            hash_prefix = {
                'list_name': chunk.list_name,
                'chunk_number': chunk.chunk_number,
                'chunk_type': chunk.chunk_type,
                'value': sqlite3.Binary(hash_value),
            }
            self.insert_hash_prefix(hash_prefix)
        self.db.commit()

    def insert_chunk(self, chunk):
        "Insert hash prefixes from the chunk to the database"
        q = 'INSERT INTO chunk (chunk_number, list_name, chunk_type) \
            VALUES (?, ?, ?)'
        self.dbc.execute(q, [chunk.chunk_number, chunk.list_name, chunk.chunk_type])

    def insert_hash_prefix(self, hash_prefix):
        "Insert individual hash prefix to the database"
        q = 'INSERT INTO hash_prefix (value, chunk_number, list_name, chunk_type) \
            VALUES (?, ?, ?, ?)'
        params = [hash_prefix[k] for k in
                        ('value', 'chunk_number', 'list_name', 'chunk_type')]
        try:
            self.dbc.execute(q, params)
        except sqlite3.IntegrityError as e:
            log.warn('Failed to insert chunk because of %s' % e)

    def store_full_hashes(self, hash_prefix, hashes):
        "Store hashes found for the given hash prefix"
        self.cleanup_expired_hashes()
        cache_lifetime = hashes['cache_lifetime']
        for list_name, hash_values in hashes['hashes'].items():
            for hash_value in hash_values:
                q = "INSERT INTO full_hash (value, list_name, downloaded_at, expires_at)\
                    VALUES (?, ?, current_timestamp, datetime(current_timestamp, '+%d SECONDS'))"
                self.dbc.execute(q % cache_lifetime, [sqlite3.Binary(hash_value), list_name])
        q = "UPDATE hash_prefix SET full_hash_expires_at=datetime(current_timestamp, '+%d SECONDS') \
            WHERE chunk_type='add' AND value=?"
        self.dbc.execute(q % cache_lifetime, [sqlite3.Binary(hash_prefix)])
        self.db.commit()

    def full_hash_sync_required(self, hash_prefix):
        """Check if hashes for the given hash prefix have expired

        and that prefix needs to be re-queried
        """
        q = "SELECT COUNT(*) FROM hash_prefix WHERE \
            full_hash_expires_at > current_timestamp AND chunk_type='add' AND value=?"
        self.dbc.execute(q, [sqlite3.Binary(hash_prefix)])
        c = self.dbc.fetchall()[0][0]
        return c == 0

    def lookup_full_hash(self, hash_value):
        "Query DB to see if hash is blacklisted"
        q = 'SELECT list_name FROM full_hash WHERE value=?'
        self.dbc.execute(q, [sqlite3.Binary(hash_value)])
        return [h[0] for h in self.dbc.fetchall()]

    def lookup_hash_prefix(self, hash_prefix):
        """Check if hash prefix is in the list and does not have 'sub'
        status signifying that it should be evicted from the blacklist
        """
        q = 'SELECT list_name FROM hash_prefix WHERE chunk_type=? AND value=?'
        self.dbc.execute(q, ['add', sqlite3.Binary(hash_prefix)])
        lists_add = [r[0] for r in self.dbc.fetchall()]
        if len(lists_add) == 0:
            return False
        self.dbc.execute(q, ['sub', sqlite3.Binary(hash_prefix)])
        lists_sub = [r[0] for r in self.dbc.fetchall()]
        if len(lists_sub) == 0:
            return True
        if set(lists_add) - set(lists_sub):
            return True
        return False

    def cleanup_expired_hashes(self):
        "Delete all hashes that behind their expiration date"
        q = 'DELETE FROM full_hash WHERE expires_at < current_timestamp'
        self.dbc.execute(q)
        self.db.commit()

    def del_add_chunks(self, chunk_numbers):
        "Delete records associated with 'add' chunk"
        if not chunk_numbers:
            return
        log.info('Deleting "add" chunks %s' % repr(chunk_numbers))
        for cn in self.expand_ranges(chunk_numbers):
            q = 'DELETE FROM chunk WHERE chunk_type=? AND chunk_number=?'
            self.dbc.execute(q, ['add', cn])
        self.db.commit()

    def del_sub_chunks(self, chunk_numbers):
        "Delete records associated with 'sub' chunk"
        if not chunk_numbers:
            return
        log.info('Deleting "sub" chunks %s' % repr(chunk_numbers))
        for cn in self.expand_ranges(chunk_numbers):
            q = 'DELETE FROM chunk WHERE chunk_type=? AND chunk_number=?'
            self.dbc.execute(q, ['sub', cn])
        self.db.commit()

    def get_existing_chunks(self):
        "Get the list of chunks that are available in the local cache"
        output = {}
        for chunk_type in ('add', 'sub'):
            q = "SELECT list_name, group_concat(chunk_number) FROM chunk \
                WHERE chunk_type=? GROUP BY list_name"
            self.dbc.execute(q, [chunk_type])
            for list_name, chunks in self.dbc.fetchall():
                if not output.has_key(list_name):
                    output[list_name] = {}
                chunks = [int(c) for c in chunks.split(',')]
                output[list_name][chunk_type] = self.compress_ranges(chunks)
        return output

    def total_cleanup(self):
        "Reset local cache"
        q = 'DROP TABLE hash_prefix'
        self.dbc.execute(q)
        q = 'DROP TABLE chunk'
        self.dbc.execute(q)
        q = 'DROP TABLE full_prefix'
        self.dbc.execute(q)
        self.db.commit()
        self.init_db()
