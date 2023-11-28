#!/usr/bin/env python

import mysql.connector
import contextlib
import hashlib

import logging as log
import gglsbl
# log = logging.getLogger()
# log.addHandler(logging.NullHandler())

class MySQLStorage(object):
    """Storage abstraction for local GSB cache in MySQL
    """

    schema_version = '1.1'

    def __init__(self, config):
        self.config = config
        self.db = None
        self.db_path = config.get('database')
        self.connect()
        if not self.check_schema_exists():
            log.info('Table Schema does not exist, initializing')
            self.init_db()

        if not self.check_schema_version():
            raise Exception("Cache schema is not compatible with this library version.")

    def connect(self):
        try:
            self.db.close()
        except:
            pass
        self.db = mysql.connector.connect(user = self.config['user'], password = self.config['password'],
                                          host = self.config['host'], database = self.config['database'],
                                          time_zone='+00:00', use_pure=True)

    @contextlib.contextmanager
    def get_cursor(self):
        if self.db is None:
            self.connect()
        else:
            self.ping()

        dbc = self.db.cursor()
        try:
            yield dbc
        finally:
            dbc.close()

    def ping(self):
        try:
            self.db.ping(reconnect=True)
        except Exception, e:
            log.error(e)

    def check_schema_exists(self):
        """ check if tables already exists
        """
        with self.get_cursor() as dbc:
            dbc.execute("""
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_name = 'metadata'""")
            if dbc.fetchone()[0] == 1:
                return True

    def check_schema_version(self):
        q = "SELECT value FROM metadata WHERE name='schema_version'"
        v = None
        with self.get_cursor() as dbc:
            try:
                dbc.execute(q)
                v = dbc.fetchone()
                if not v:
                    return False
            except mysql.connector.errors.OperationalError:
                log.error('Can not get schema version, it is probably outdated.')
                return False
        self.rollback()  # prevent dangling transaction while instance is idle after init
        return v[0] == self.schema_version

    def init_db(self):
        """initialize database schema
        """
        with self.get_cursor() as dbc:
            dbc.execute("""SET FOREIGN_KEY_CHECKS=0;""")
            dbc.execute("""
            CREATE TABLE IF NOT EXISTS `full_hash` (
                `value` VARBINARY(32) NOT NULL,
                `threat_type` varchar(128) COLLATE ascii_general_ci NOT NULL,
                `platform_type` varchar(128) COLLATE ascii_general_ci NOT NULL,
                `threat_entry_type` varchar(128) COLLATE ascii_general_ci NOT NULL,
                `downloaded_at` datetime NOT NULL,
                `expires_at` datetime NOT NULL,
                `malware_threat_type` varchar(32) COLLATE ascii_general_ci DEFAULT NULL,
                PRIMARY KEY (`value`(32),`threat_type`,`platform_type`,`threat_entry_type`),
                KEY `idx_full_hash_expires_at` (`expires_at`),
                KEY `idx_full_hash_value` (`value`)
            ) ENGINE=InnoDB;
            """)

            dbc.execute("""
            CREATE TABLE IF NOT EXISTS `hash_prefix` (
                `value` VARBINARY(32) NOT NULL,
                `cue` BINARY(4) NOT NULL,
                `threat_type` varchar(128) COLLATE ascii_general_ci NOT NULL,
                `platform_type` varchar(128) COLLATE ascii_general_ci NOT NULL,
                `threat_entry_type` varchar(128) COLLATE ascii_general_ci NOT NULL,
                `timestamp` datetime NOT NULL,
                `negative_expires_at` datetime NOT NULL,
                PRIMARY KEY (`value`,`threat_type`,`platform_type`,`threat_entry_type`),
                KEY `idx_hash_prefix_cue` (`cue`),
                KEY `idx_hash_prefix_list` (`threat_type`,`platform_type`,`threat_entry_type`),
                CONSTRAINT `hash_prefix_ibfk_1`
                    FOREIGN KEY (`threat_type`, `platform_type`, `threat_entry_type`)
                    REFERENCES `threat_list` (`threat_type`, `platform_type`, `threat_entry_type`)
                    ON DELETE CASCADE
            ) ENGINE=InnoDB;
            """)

            dbc.execute("""
            CREATE TABLE IF NOT EXISTS `metadata` (
                `name` varchar(128) COLLATE ascii_general_ci NOT NULL,
                `value` varchar(128) COLLATE ascii_general_ci NOT NULL,
                PRIMARY KEY (`name`)
            ) ENGINE=InnoDB;
            """)

            dbc.execute(
                """INSERT IGNORE INTO metadata (name, value) VALUES ('schema_version', %s)""", (self.schema_version, )
            )

            dbc.execute("""
            CREATE TABLE IF NOT EXISTS `threat_list` (
                `threat_type` varchar(128) COLLATE ascii_general_ci NOT NULL,
                `platform_type` varchar(128) COLLATE ascii_general_ci NOT NULL,
                `threat_entry_type` varchar(128) COLLATE ascii_general_ci NOT NULL,
                `client_state` varchar(42) COLLATE ascii_general_ci DEFAULT NULL,
                `timestamp` datetime NOT NULL,
                PRIMARY KEY (`threat_type`,`platform_type`,`threat_entry_type`)
            ) ENGINE=InnoDB;
            """)
            dbc.execute("""SET FOREIGN_KEY_CHECKS=1;""")

        self.commit()

    def lookup_full_hashes(self, hash_values, return_values = None):
        """Query DB to see if hash is blacklisted
        """
        q = """SELECT threat_type, platform_type, threat_entry_type, expires_at < NOW() AS has_expired, value
                FROM full_hash WHERE value IN ({})"""
        output = []
        with self.get_cursor() as dbc:
            placeholders = ','.join(['%s'] * len(hash_values))
            dbc.execute(q.format(placeholders), list(hash_values))
            for h in dbc.fetchall():
                threat_type, platform_type, threat_entry_type, has_expired, matched_value = h
                threat_list = gglsbl.storage.ThreatList(threat_type, platform_type, threat_entry_type)
                if return_values:
                    output.append((threat_list, has_expired, bytes(matched_value)))
                else:
                    output.append((threat_list, has_expired))
        return output

    def lookup_hash_prefix(self, cues):
        """Lookup hash prefixes by cue (first 4 bytes of hash)

        Returns a tuple of (value, negative_cache_expired).
        """
        q = """SELECT value, MAX(negative_expires_at < NOW()) AS negative_cache_expired
                FROM hash_prefix WHERE cue IN ({}) GROUP BY 1"""
        output = []
        with self.get_cursor() as dbc:
            dbc.execute(q.format(','.join(['%s'] * len(cues))), list(cues))
            for h in dbc.fetchall():
                value, negative_cache_expired = h
                output.append((bytes(value), negative_cache_expired))
        return output

    def store_full_hash(self, threat_list, hash_value, cache_duration, malware_threat_type):
        """Store full hash found for the given hash prefix"""
        log.info('Storing full hash %s to list %s with cache duration %s',
                 hash_value.encode('hex'), str(threat_list), cache_duration)
        q = """INSERT INTO full_hash
                    (value, threat_type, platform_type, threat_entry_type, malware_threat_type, downloaded_at, expires_at)
                VALUES
                    (%s, %s, %s, %s, %s, NOW(), DATE_ADD(NOW(), INTERVAL {} SECOND))
                    ON DUPLICATE KEY UPDATE expires_at = DATE_ADD(NOW(), INTERVAL {} SECOND)"""

        parameters = [bytes(hash_value), threat_list.threat_type,
                      threat_list.platform_type, threat_list.threat_entry_type, malware_threat_type]

        with self.get_cursor() as dbc:
            dbc.execute(q.format(int(cache_duration), int(cache_duration)), parameters)

    def delete_hash_prefix_list(self, threat_list):
        q = "DELETE FROM hash_prefix WHERE threat_type=%s AND platform_type=%s AND threat_entry_type=%s"
        parameters = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, parameters)

    def cleanup_full_hashes(self, keep_expired_for=(60 * 60 * 12)):
        """Remove long expired full_hash entries."""
        q = 'DELETE FROM full_hash WHERE expires_at < DATE_SUB(NOW(), INTERVAL {} SECOND)'
        log.info('Cleaning up full_hash entries expired more than {} seconds ago.'.format(keep_expired_for))
        with self.get_cursor() as dbc:
            dbc.execute(q.format(int(keep_expired_for)))

    def update_hash_prefix_expiration(self, prefix_value, negative_cache_duration):
        q = "UPDATE hash_prefix SET negative_expires_at = DATE_ADD(NOW(), INTERVAL {} SECOND) WHERE value=%s"
        parameters = [prefix_value, ]
        with self.get_cursor() as dbc:
            dbc.execute(q.format(int(negative_cache_duration)), parameters)

    def get_threat_lists(self):
        """Get a list of known threat lists."""
        q = 'SELECT threat_type, platform_type, threat_entry_type FROM threat_list'
        output = []
        with self.get_cursor() as dbc:
            dbc.execute(q)
            for h in dbc.fetchall():
                threat_type, platform_type, threat_entry_type = h
                threat_list = gglsbl.storage.ThreatList(threat_type, platform_type, threat_entry_type)
                output.append(threat_list)
        return output

    def get_client_state(self):
        """Get a dict of known threat lists including clientState values."""
        q = 'SELECT threat_type, platform_type, threat_entry_type, client_state FROM threat_list'
        output = {}
        with self.get_cursor() as dbc:
            dbc.execute(q)
            for h in dbc.fetchall():
                threat_type, platform_type, threat_entry_type, client_state = h
                threat_list_tuple = (threat_type, platform_type, threat_entry_type)
                output[threat_list_tuple] = client_state
        return output

    def add_threat_list(self, threat_list):
        """Add threat list entry if it does not exist."""
        q = '''INSERT IGNORE INTO threat_list
                    (threat_type, platform_type, threat_entry_type, timestamp)
                VALUES
                    (%s, %s, %s, NOW())
        '''
        params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, params)

    def delete_threat_list(self, threat_list):
        """Delete threat list entry."""
        log.info('Deleting cached threat list "{}"'.format(repr(threat_list)))
        q = 'DELETE FROM threat_list WHERE threat_type=%s AND platform_type=%s AND threat_entry_type=%s'
        params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, params)

    def update_threat_list_client_state(self, threat_list, client_state):
        log.info('Setting client_state in DB')
        q = """UPDATE threat_list SET timestamp=NOW(), client_state=%s WHERE
                threat_type=%s AND platform_type=%s AND threat_entry_type=%s"""
        with self.get_cursor() as dbc:
            params = [client_state, threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
            dbc.execute(q, params)

    def hash_prefix_list_checksum(self, threat_list):
        """Returns SHA256 checksum for alphabetically-sorted concatenated list of hash prefixes"""
        q = '''SELECT value FROM hash_prefix
                WHERE threat_type=%s AND platform_type=%s AND threat_entry_type=%s
            ORDER BY value
        '''
        params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, params)
            all_hashes = b''.join(bytes(h[0]) for h in dbc.fetchall())
            checksum = hashlib.sha256(all_hashes).digest()
        return checksum

    def populate_hash_prefix_list(self, threat_list, hash_prefix_list):
        log.info('Storing {} entries of hash prefix list {}'.format(len(hash_prefix_list), str(threat_list)))
        q = '''INSERT INTO hash_prefix
                    (value, cue, threat_type, platform_type, threat_entry_type, timestamp, negative_expires_at)
                VALUES
                    (%s, %s, %s, %s, %s, NOW(), NOW())
        '''
        with self.get_cursor() as dbc:
            records = [[prefix_value, prefix_value[0:4], threat_list.threat_type,
                        threat_list.platform_type, threat_list.threat_entry_type] for prefix_value in hash_prefix_list]
            dbc.executemany(q, records)

    def get_hash_prefix_values_to_remove(self, threat_list, indices):
        log.info('Removing {} records from threat list "{}"'.format(len(indices), str(threat_list)))
        indices = set(indices)
        q = '''SELECT value FROM hash_prefix
                WHERE threat_type=%s AND platform_type=%s AND threat_entry_type=%s
                ORDER BY value
        '''
        params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        values_to_remove = []
        with self.get_cursor() as dbc:
            dbc.execute(q, params)
            av = dbc.fetchall()
            for i in indices:
                v = bytes(av[i][0])
                values_to_remove.append(v)
        return values_to_remove

    def remove_hash_prefix_indices(self, threat_list, indices):
        """Remove records matching idices from a lexicographically-sorted local threat list."""
        batch_size = 40
        q = """DELETE FROM hash_prefix WHERE
            threat_type=%s AND platform_type=%s AND threat_entry_type=%s AND value IN ({})"""
        prefixes_to_remove = self.get_hash_prefix_values_to_remove(threat_list, indices)
        with self.get_cursor() as dbc:
            for i in range(0, len(prefixes_to_remove), batch_size):
                remove_batch = prefixes_to_remove[i:(i + batch_size)]
                params = [
                    threat_list.threat_type,
                    threat_list.platform_type,
                    threat_list.threat_entry_type
                ] + remove_batch
                dbc.execute(q.format(','.join(['%s'] * len(remove_batch))), params)

    def dump_hash_prefix_values(self):
        """Export all hash prefix values.

        Returns a list of known hash prefix values
        """
        q = 'SELECT distinct value from hash_prefix'
        output = []
        with self.get_cursor() as dbc:
            dbc.execute(q)
            output = [bytes(r[0]) for r in dbc.fetchall()]
        return output

    def rollback(self):
        log.info('Rolling back DB transaction.')
        try:
            self.db.rollback()
        except mysql.connector.errors.OperationalError, e:
            if e.errno == 2055:
                return self.connect()
            raise e

    def commit(self):
        self.db.commit()

    def total_cleanup(self):
        """Reset local cache
        """
        with self.get_cursor() as dbc:
            dbc.execute("DROP TABLE metadata")
            dbc.execute("DROP TABLE threat_list")
            dbc.execute("DROP TABLE full_hash")
            dbc.execute("DROP TABLE hash_prefix")
        self.commit()
        self.init_db()
