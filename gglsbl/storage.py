#!/usr/bin/env python

import os
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
        self.dbc = self.db.cursor()
        if do_init_db:
            log.info('SQLite DB does not exist, initializing')
            self.init_db()
        self.dbc.execute('PRAGMA synchronous = 0')

    def init_db(self):
        self.dbc.execute(
        """CREATE TABLE threat_list (
            threat_type character varying(128) NOT NULL,
            platform_type character varying(128) NOT NULL,
            threat_entry_type character varying(128) NOT NULL,
            client_state character varying(42),
            timestamp timestamp DEFAULT current_timestamp,
            PRIMARY KEY (threat_type, platform_type, threat_entry_type)
            )"""
        )
        self.dbc.execute(
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
        self.dbc.execute(
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
#        self.dbc.execute(
#            """CREATE INDEX idx_hash_prefix_chunk_id ON hash_prefix (chunk_number, list_name, chunk_type_sub)"""
#        )
        self.dbc.execute(
            """CREATE INDEX idx_full_hash_expires_at ON full_hash (expires_at)"""
        )
        self.db.commit()



    def lookup_full_hash(self, hash_value):
        "Query DB to see if hash is blacklisted"
        q = '''SELECT threat_type,platform_type,threat_entry_type
                FROM full_hash WHERE value=? AND expires_at < current_timestamp
        '''
        self.dbc.execute(q, [sqlite3.Binary(hash_value)])
        output = []
        for h in self.dbc.fetchall():
            threat_type, platform_type, threat_entry_type = h
            threat_list = ThreatList(threat_type, platform_type, threat_entry_type)
            output.append(threat_list)
        return output

    def lookup_hash_prefix(self, hash_prefix):
        q = '''SELECT threat_type,platform_type,threat_entry_type
                    neagative_expires_at > current_timetsamp AS negative_cache_expired
                FROM hash_prefix WHERE value=?
        '''
        self.dbc.execute(q, [sqlite3.Binary(hash_value)])
        output = []
        for h in self.dbc.fetchall():
            threat_type, platform_type, threat_entry_type = h
            threat_list = ThreatList(threat_type, platform_type, threat_entry_type)
            output.append((threat_list, negative_cache_expired))
        return output

    def store_full_hash(self, threat_list, hash_value, cache_duration, malware_threat_type):
        "Store full hash found for the given hash prefix"
        q = '''INSERT OR IGNORE INTO full_hash
                    (value, threat_type, platform_type, threat_entry_type, malware_threat_type, downloaded_at)
                VALUES
                    (?, ?, ?, ?, current_timestamp)
        '''
        params = [sqlite3.Binary(hash_value), threat_list.threat_type,
                    threat_list.platform_type, threat_list.threat_entry_type, malware_threat_type]
        self.dbc.execute(q, params)
        q = "UPDATE full_hash SET expires_at=datetime(current_timestamp, '+%d SECONDS') \
            WHERE value=? AND threat_type=? AND platform_type=? AND threat_entry_type=?"
        parameters = [sqlite3.Binary(hash_value), threat_list.threat_type,
                    threat_list.platform_type, threat_list.threat_entry_type]
        self.dbc.execute(q % int(cache_duration), parameters)
        self.db.commit()

    def delete_hash_prefix_list(self, threat_list):
        q = '''DELETE FROM hash_prefix
                    WHERE threat_type=? AND platform_type=? AND threat_entry_type=?
        '''
        parameters = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        self.dbc.execute(q, parameters)
        self.db.commit()

    def update_hash_prefix_expiration(self, threat_list, prefix_value, negative_cache_expires_at):
        q = "UPDATE hash_prefix SET negative_cache_expires_at=datetime(current_timestamp, '+%d SECONDS') \
            WHERE value=? AND threat_type=? AND platform_type=? AND threat_entry_type=?"
        parameters = [sqlite3.Binary(prefix_value), threat_list.threat_type,
                    threat_list.platform_type, threat_list.threat_entry_type]
        self.dbc.execute(q % int(negative_cache_expires_at), parameters)
        self.db.commit()

    def get_threat_lists(self):
        q = '''SELECT threat_type,platform_type,threat_entry_type,client_state FROM threat_list'''
        self.dbc.execute(q)
        output = []
        for h in self.dbc.fetchall():
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
        self.dbc.execute(q, params)
        self.db.commit()

    def update_threat_list_client_state(self, threat_list, client_state):
        log.info('Setting client_state of threat list {} to {}'.format(str(threat_list), client_state))
        q = '''UPDATE threat_list SET timestamp=current_timestamp, client_state=?
            WHERE threat_type=? AND platform_type=? AND threat_entry_type=?'''
        params = [client_state, threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        self.dbc.execute(q, params)
        self.db.commit()

    def hash_prefix_list_checksum(self, threat_list):
        pass

    def add_hash_prefix_list(self, threat_list, hash_prefix_list):
        log.info('Storing {} entries of hash prefix list {}'.format(len(hash_prefix_list), str(threat_list)))
        q = '''INSERT INTO hash_prefix
                    (value, threat_type, platform_type, threat_entry_type, timestamp)
                VALUES
                    (?, ?, ?, ?, current_timestamp)
        '''
        for prefix_value in hash_prefix_list:
            params = [sqlite3.Binary(prefix_value), threat_list.threat_type,
                    threat_list.platform_type, threat_list.threat_entry_type]
            self.dbc.execute(q, params)
        self.db.commit()

    def remove_hash_prefix_indices(self, threat_list, indices):
        return

    def total_cleanup(self):
        "Reset local cache"
        q = 'DROP TABLE threat_list'
        self.dbc.execute(q)
        q = 'DROP TABLE hash_prefix'
        self.dbc.execute(q)
        q = 'DROP TABLE full_prefix'
        self.dbc.execute(q)
        self.db.commit()
        self.init_db()
