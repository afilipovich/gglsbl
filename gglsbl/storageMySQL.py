#!/usr/bin/env python

import mysql.connector

import logging
log = logging.getLogger()
log.addHandler(logging.NullHandler())

from .storage import StorageBase

class MySQLStorage(StorageBase):
    """Storage abstraction for local GSB cache in MySQL
    """
    def __init__(self, config):
        self.config = config
        self.db = mysql.connector.connect(user = config['user'], password = config['password'], host = config['host'], database = config['database'], time_zone='+00:00')
        self.dbc = self.db.cursor()
        if not self.check_schema_exists():
            self.init_db()

    def check_schema_exists(self):
        """ check if tables already exists
        """
        self.dbc.execute("""
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_name = 'chunk'""")
        if self.dbc.fetchone()[0] == 1:
            return True

    def init_db(self):
        """initialize database schema
        """
        self.dbc.execute("""
            CREATE TABLE IF NOT EXISTS `chunk` (
              `chunk_number` int(11) UNSIGNED NOT NULL,
              `timestamp` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
              `list_name` varchar(127) NOT NULL,
              `chunk_type` enum('add','sub') NOT NULL,
              PRIMARY KEY (`chunk_number`,`list_name`,`chunk_type`)
            ) ENGINE=InnoDB DEFAULT CHARSET=ascii;
        """
        )

        self.dbc.execute("""
            CREATE TABLE IF NOT EXISTS `full_hash` (
              `value` binary(32) NOT NULL,
              `list_name` varchar(127) NOT NULL,
              `downloaded_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
              `expires_at` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
              PRIMARY KEY (`value`)
            ) ENGINE=InnoDB DEFAULT CHARSET=ascii;
            """
        )

        self.dbc.execute("""
            CREATE TABLE IF NOT EXISTS `hash_prefix` (
              `value` binary(4) NOT NULL,
              `chunk_number` int(11) unsigned NOT NULL,
              `timestamp` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
              `list_name` varchar(127) NOT NULL,
              `chunk_type` enum('add','sub') NOT NULL,
              `full_hash_expires_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (`value`,`chunk_number`,`list_name`,`chunk_type`),
              KEY `FK_hash_prefix_chunk` (`chunk_number`,`list_name`,`chunk_type`),
              CONSTRAINT `FK_hash_prefix_chunk` FOREIGN KEY (`chunk_number`, `list_name`, `chunk_type`) REFERENCES `chunk` (`chunk_number`, `list_name`, `chunk_type`) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=ascii;
            """
        )
        self.db.commit()

    def chunk_exists(self, chunk):
        """Check if given chunk records already exist in the database
        """
        q = 'SELECT COUNT(*) FROM chunk WHERE chunk_number=%s AND chunk_type=%s AND list_name=%s'
        self.dbc.execute(q, [chunk.chunk_number, chunk.chunk_type, chunk.list_name])
        if self.dbc.fetchone()[0] > 0:
            return True
        return False

    def store_chunk(self, chunk):
        """Store chunk in the database
        """
        log.debug('Storing %s chunk #%s for list name %s' % (chunk.chunk_type, chunk.chunk_number, chunk.list_name))
        self.insert_chunk(chunk)
        for hash_value in chunk.hashes:
            hash_prefix = {
                'list_name': chunk.list_name,
                'chunk_number': chunk.chunk_number,
                'chunk_type': chunk.chunk_type,
                'value': hash_value[0:4],
            }
            self.insert_hash_prefix(hash_prefix)
        self.db.commit()

    def insert_chunk(self, chunk):
        """Insert hash prefixes from the chunk to the database
        """
        self.dbc.execute("""INSERT INTO chunk (chunk_number, list_name, chunk_type) VALUES (%s, %s, %s)""", \
                          [chunk.chunk_number, chunk.list_name, chunk.chunk_type])

    def insert_hash_prefix(self, hash_prefix):
        """Insert individual hash prefix to the database
        """
        q = 'INSERT INTO hash_prefix (value, chunk_number, list_name, chunk_type) VALUES (x%s, %s, %s, %s)'
        try:
            self.dbc.execute(q, (hash_prefix['value'].encode('hex'), hash_prefix['chunk_number'], hash_prefix['list_name'], hash_prefix['chunk_type']))
        except mysql.connector.IntegrityError as e:
            log.warn('Failed to insert chunk because of %s' % e)

    def store_full_hashes(self, hash_prefix, hashes):
        """Store hashes found for the given hash prefix
        """
        self.cleanup_expired_hashes()
        cache_lifetime = hashes['cache_lifetime']
        for list_name, hash_values in hashes['hashes'].items():
            for hash_value in hash_values:
                self.dbc.execute( """INSERT IGNORE INTO full_hash (value, list_name, downloaded_at, expires_at)
                    VALUES (x%s, %s, NOW(), DATE_ADD(NOW(), INTERVAL %s SECOND))""", \
                        (hash_value.encode('hex'), list_name, cache_lifetime))
        self.dbc.execute("""UPDATE hash_prefix SET full_hash_expires_at = DATE_ADD(NOW(), INTERVAL %s SECOND) WHERE chunk_type = 'add' AND value = x%s""", \
                        (cache_lifetime, hash_prefix.encode('hex'), ))
        self.db.commit()

    def full_hash_sync_required(self, hash_prefix):
        """Check if hashes for the given hash prefix have expired
           and that prefix needs to be re-queried
        """
        self.dbc.execute("""SELECT COUNT(*) FROM hash_prefix WHERE full_hash_expires_at > NOW() AND chunk_type='add' AND value=x%s""", \
                        (hash_prefix.encode('hex'), ))
        c = self.dbc.fetchone()[0]
        return c == 0

    def lookup_full_hash(self, hash_value):
        """Query DB to see if hash is blacklisted
        """
        self.dbc.execute("""SELECT list_name FROM full_hash WHERE value=x%s""", (hash_value.encode('hex'), ))
        return [h[0] for h in self.dbc.fetchall()]

    def lookup_hash_prefix(self, hash_prefix):
        """Check if hash prefix is in the list and does not have 'sub'
           status signifying that it should be evicted from the blacklist
        """
        q = """SELECT list_name FROM hash_prefix WHERE chunk_type = %s AND value = x%s"""
        self.dbc.execute(q, ('add', hash_prefix.encode('hex')))
        lists_add = [r[0] for r in self.dbc.fetchall()]
        if len(lists_add) == 0:
            return False
        self.dbc.execute(q, ('sub', hash_prefix.encode('hex')))
        lists_sub = [r[0] for r in self.dbc.fetchall()]
        if len(lists_sub) == 0:
            return True
        if set(lists_add) - set(lists_sub):
            return True
        return False

    def cleanup_expired_hashes(self):
        """Delete all hashes that behind their expiration date
        """
        self.dbc.execute("""DELETE FROM full_hash WHERE expires_at < NOW()""")
        self.db.commit()

    def del_add_chunks(self, chunk_numbers):
        """Delete records associated with 'add' chunk
        """
        if not chunk_numbers:
            return
        log.info('Deleting "add" chunks %s' % repr(chunk_numbers))
        for cn in self.expand_ranges(chunk_numbers):
            self.dbc.execute("""DELETE FROM chunk WHERE chunk_type=%s AND chunk_number=%s""", ('add', cn))
        self.db.commit()

    def del_sub_chunks(self, chunk_numbers):
        """Delete records associated with 'sub' chunk
        """
        if not chunk_numbers:
            return
        log.info('Deleting "sub" chunks %s' % repr(chunk_numbers))
        for cn in self.expand_ranges(chunk_numbers):
            self.dbc.execute("""DELETE FROM chunk WHERE chunk_type=%s AND chunk_number=%s""", ('sub', cn))
        self.db.commit()

    def get_existing_chunks(self):
        """Get the list of chunks that are available in the local cache
        """
        output = {}
        for chunk_type in ('add', 'sub'):
            self.dbc.execute("""SELECT list_name, group_concat(chunk_number) FROM chunk WHERE chunk_type = %s GROUP BY list_name""", (chunk_type, ))
            for list_name, chunks in self.dbc:
                if not output.has_key(list_name):
                    output[list_name] = {}
                chunks = [int(c) for c in chunks.split(',')]
                output[list_name][chunk_type] = self.compress_ranges(chunks)
        return output

    def total_cleanup(self):
        """Reset local cache
        """
        self.dbc.execute("""DROP TABLE hash_prefix""")
        self.dbc.execute("""DROP TABLE chunk""")
        self.dbc.execute("""DROP TABLE full_prefix""")
        self.db.commit()
        self.init_db()
