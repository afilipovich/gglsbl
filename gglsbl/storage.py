#!/usr/bin/env python

import os
import hashlib
import contextlib
import sqlite3

import logging
log = logging.getLogger()
log.addHandler(logging.NullHandler())


class ThreatList(object):
    def __init__(self, threat_type, platform_type, threat_entry_type):
        self.threat_type = threat_type
        self.platform_type = platform_type
        self.threat_entry_type = threat_entry_type

    @classmethod
    def from_api_entry(cls, entry):
        return cls(entry['threatType'], entry['platformType'], entry['threatEntryType'])

    def __repr__(self):
        return '/'.join([self.threat_type, self.platform_type, self.threat_entry_type])


class HashPrefixList(object):
    def __init__(self, prefix_size, raw_hashes):
        self.prefix_size = prefix_size
        self.raw_hashes = raw_hashes

    def __len__(self):
        return int(len(self.raw_hashes) / self.prefix_size)

    def __iter__(self):
        n = self.prefix_size
        return (self.raw_hashes[i:i+n] for i in xrange(0, len(self.raw_hashes), n))


class SqliteStorage(object):
    """Storage abstraction for local GSB cache"""
    def __init__(self, db_path):
        self.db_path = db_path
        do_init_db = not os.path.isfile(db_path)
        log.info('Opening SQLite DB %s' % db_path)
        self.db = sqlite3.connect(db_path)
        if do_init_db:
            log.info('SQLite DB does not exist, initializing')
            self.init_db()
        self.db.cursor().execute('PRAGMA synchronous = 0')

    @contextlib.contextmanager
    def get_cursor(self):
        dbc = self.db.cursor()
        try:
            yield dbc
        finally:
            dbc.close()

    def init_db(self):
        with self.get_cursor() as dbc:
            dbc.execute(
            """CREATE TABLE threat_list (
                threat_type character varying(128) NOT NULL,
                platform_type character varying(128) NOT NULL,
                threat_entry_type character varying(128) NOT NULL,
                client_state character varying(42),
                timestamp timestamp DEFAULT current_timestamp,
                PRIMARY KEY (threat_type, platform_type, threat_entry_type)
                )"""
            )
            dbc.execute(
            """CREATE TABLE full_hash (
                value BLOB NOT NULL,
                threat_type character varying(128) NOT NULL,
                platform_type character varying(128) NOT NULL,
                threat_entry_type character varying(128) NOT NULL,
                downloaded_at timestamp DEFAULT current_timestamp,
                expires_at timestamp without time zone NOT NULL,
                malware_threat_type varchar(32),
                PRIMARY KEY (value, threat_type, platform_type, threat_entry_type)
                )"""
            )
            dbc.execute(
            """CREATE TABLE hash_prefix (
                value BLOB NOT NULL,
                threat_type character varying(128) NOT NULL,
                platform_type character varying(128) NOT NULL,
                threat_entry_type character varying(128) NOT NULL,
                timestamp timestamp without time zone DEFAULT current_timestamp,
                negative_expires_at timestamp NOT NULL DEFAULT current_timestamp,
                PRIMARY KEY (value, threat_type, platform_type, threat_entry_type),
                FOREIGN KEY(threat_type, platform_type, threat_entry_type)
                    REFERENCES threat_list(threat_type, platform_type, threat_entry_type)
                    ON DELETE CASCADE
                )"""
            )
    #        dbc.execute(
    #            """CREATE INDEX idx_hash_prefix_chunk_id ON hash_prefix (chunk_number, list_name, chunk_type_sub)"""
    #        )
            dbc.execute(
                """CREATE INDEX idx_full_hash_expires_at ON full_hash (expires_at)"""
            )
        self.db.commit()



    def lookup_full_hash(self, hash_value):
        "Query DB to see if hash is blacklisted"
        q = '''SELECT threat_type,platform_type,threat_entry_type
                FROM full_hash WHERE value=? AND expires_at < current_timestamp
        '''
        output = []
        with self.get_cursor() as dbc:
            dbc.execute(q, [sqlite3.Binary(hash_value)])
            for h in dbc.fetchall():
                threat_type, platform_type, threat_entry_type = h
                threat_list = ThreatList(threat_type, platform_type, threat_entry_type)
                output.append(threat_list)
        return output

    def lookup_hash_prefix(self, hash_prefix):
        q = '''SELECT threat_type,platform_type,threat_entry_type
                    neagative_expires_at > current_timetsamp AS negative_cache_expired
                FROM hash_prefix WHERE value=?
        '''
        output = []
        with self.get_cursor() as dbc:
            execute(q, [sqlite3.Binary(hash_value)])
            for h in dbc.fetchall():
                threat_type, platform_type, threat_entry_type = h
                threat_list = ThreatList(threat_type, platform_type, threat_entry_type)
                output.append((threat_list, negative_cache_expired))
        return output

    def store_full_hash(self, threat_list, hash_value, cache_duration, malware_threat_type):
        "Store full hash found for the given hash prefix"
        qi = '''INSERT OR IGNORE INTO full_hash
                    (value, threat_type, platform_type, threat_entry_type, malware_threat_type, downloaded_at)
                VALUES
                    (?, ?, ?, ?, current_timestamp)
        '''
        qu = "UPDATE full_hash SET expires_at=datetime(current_timestamp, '+%d SECONDS') \
            WHERE value=? AND threat_type=? AND platform_type=? AND threat_entry_type=?"

        i_parameters = [sqlite3.Binary(hash_value), threat_list.threat_type,
                    threat_list.platform_type, threat_list.threat_entry_type, malware_threat_type]
        u_parameters = [sqlite3.Binary(hash_value), threat_list.threat_type,
                    threat_list.platform_type, threat_list.threat_entry_type]

        with self.get_cursor() as dbc:
            dbc.execute(qi, i_parameters)
            dbc.execute(qu % int(cache_duration), u_parameters)
        self.db.commit()

    def delete_hash_prefix_list(self, threat_list):
        q = '''DELETE FROM hash_prefix
                    WHERE threat_type=? AND platform_type=? AND threat_entry_type=?
        '''
        parameters = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, parameters)
        self.db.commit()

    def update_hash_prefix_expiration(self, threat_list, prefix_value, negative_cache_expires_at):
        q = "UPDATE hash_prefix SET negative_cache_expires_at=datetime(current_timestamp, '+%d SECONDS') \
            WHERE value=? AND threat_type=? AND platform_type=? AND threat_entry_type=?"
        parameters = [sqlite3.Binary(prefix_value), threat_list.threat_type,
                    threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q % int(negative_cache_expires_at), parameters)
        self.db.commit()

    def get_threat_lists(self):
        q = '''SELECT threat_type,platform_type,threat_entry_type,client_state FROM threat_list'''
        output = []
        with self.get_cursor() as dbc:
            dbc.execute(q)
            for h in dbc.fetchall():
                threat_type, platform_type, threat_entry_type, client_state = h
                threat_list = ThreatList(threat_type, platform_type, threat_entry_type)
                output.append((threat_list, client_state))
        return output

    def add_threat_list(self, threat_list):
        q = '''INSERT OR IGNORE INTO threat_list
                    (threat_type, platform_type, threat_entry_type, timestamp)
                VALUES
                    (?, ?, ?, current_timestamp)
        '''
        params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, params)
        self.db.commit()

    def update_threat_list_client_state(self, threat_list, client_state):
        log.info('Setting client_state of threat list {} to {}'.format(str(threat_list), client_state))
        q = '''UPDATE threat_list SET timestamp=current_timestamp, client_state=?
            WHERE threat_type=? AND platform_type=? AND threat_entry_type=?'''
        params = [client_state, threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, params)
        self.db.commit()

    def hash_prefix_list_checksum(self, threat_list):
        """Returns SHA256 checksum for alphabetically-sorted concatenated list of hash prefixes
        """
        q = '''SELECT value FROM hash_prefix
                WHERE threat_type=? AND platform_type=? AND threat_entry_type=?
                ORDER BY value
        '''
        params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, params)
            all_hashes = ''.join([ str(h[0]) for h in dbc.fetchall() ])
            checksum = hashlib.sha256(all_hashes).digest()
        return checksum

    def populate_hash_prefix_list(self, threat_list, hash_prefix_list):
        log.info('Storing {} entries of hash prefix list {}'.format(len(hash_prefix_list), str(threat_list)))
        q = '''INSERT INTO hash_prefix
                    (value, threat_type, platform_type, threat_entry_type, timestamp)
                VALUES
                    (?, ?, ?, ?, current_timestamp)
        '''
        with self.get_cursor() as dbc:
            for prefix_value in hash_prefix_list:
                params = [sqlite3.Binary(prefix_value), threat_list.threat_type,
                        threat_list.platform_type, threat_list.threat_entry_type]
                dbc.execute(q, params)
        #self.db.commit()

    def get_hash_prefix_values_to_remove(self, threat_list, indices):
        log.info('Removing {} records from threat list "{}"'.format(len(indices), str(threat_list)))
        indices = set(indices)
        q = '''SELECT value FROM hash_prefix
                WHERE threat_type=? AND platform_type=? AND threat_entry_type=?
                ORDER BY value
        '''
        params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        values_to_remove = []
        with self.get_cursor() as dbc:
            dbc.execute(q, params)
            i = 0
            for h in dbc.fetchall():
                v = h[0]
                if i in indices:
                    values_to_remove.append(v)
                i += 1
        return values_to_remove

    def remove_hash_prefix_indices(self, threat_list, indices):
        """Remove records matching idices from a lexicographically-sorted local threat list.
        """
        batch_size = 40
        q = '''DELETE FROM hash_prefix
                WHERE threat_type=? AND platform_type=? AND threat_entry_type=? AND value IN ({})
        '''
        prefixes_to_remove = self.get_hash_prefix_values_to_remove(threat_list, indices)
        with self.get_cursor() as dbc:
            for i in xrange(0, len(prefixes_to_remove), batch_size):
                remove_batch = prefixes_to_remove[i:(i+batch_size)]
                params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type] + \
                                map(sqlite3.Binary, remove_batch)
                dbc.execute(q.format(','.join(['?'] * len(remove_batch))), params)

    def total_cleanup(self):
        "Reset local cache"
        with self.get_cursor() as dbc:
            q = 'DROP TABLE threat_list'
            dbc.execute(q)
            q = 'DROP TABLE hash_prefix'
            dbc.execute(q)
            q = 'DROP TABLE full_prefix'
            dbc.execute(q)
        self.db.commit()
        self.init_db()
