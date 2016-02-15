#!/usr/bin/env python

import os
import datetime

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Table, Column, ForeignKeyConstraint, Integer, String, Boolean, Binary, DateTime
from sqlalchemy import create_engine, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import select

import logging
log = logging.getLogger()
log.addHandler(logging.NullHandler())


SqlAlchemyBase = declarative_base()


def now():
    return datetime.datetime.utcnow()

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


class Chunk(SqlAlchemyBase):
    __tablename__ = "chunk"
    chunk_number = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=now)
    list_name = Column(String(127), nullable=False, primary_key=True, index=True)
    chunk_type_sub = Column(Boolean, nullable=False, primary_key=True, index=True) # True for 'add', False for 'sub'


class FullHash(SqlAlchemyBase):
    __tablename__ = "full_hash"
    value = Column(Binary, nullable=False, primary_key=True)
    list_name = Column(String(127))
    downloaded_at = Column(DateTime, default=now)
    expires_at = Column(DateTime, nullable=False, index=True)


class HashPrefix(SqlAlchemyBase):
    __tablename__ = "hash_prefix"
    __table_args__ = (
        ForeignKeyConstraint(
            ['chunk_number','list_name', 'chunk_type_sub'],
            ['chunk.chunk_number','chunk.list_name', 'chunk.chunk_type_sub'],
            ondelete='CASCADE'),
    )
    value = Column(Binary, nullable=False, primary_key=True, index=True)
    chunk_number = Column(Integer, nullable=False, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, default=now)
    list_name = Column(String(127), nullable=False, primary_key=True, index=True)
    chunk_type_sub = Column(Boolean, nullable=False, primary_key=True)
    full_hash_expires_at = Column(DateTime, nullable=False, default=now)


class SqlAlchemyStorage(StorageBase):
    """Storage abstraction for local GSB cache using SQLAlchemy"""

    def __init__(self, conn_string):
        if ':' not in conn_string:
            initial_conn_string = conn_string
            conn_string = 'sqlite:///' + conn_string
            log.warn('Connection string "{}" is incompatible with SQLAlchemy. Assuming "{}" was meant.'.format(initial_conn_string, conn_string))
        self.engine = create_engine(conn_string, echo=False)
        SqlAlchemyBase.metadata.create_all(self.engine)
        if self.engine.name == 'sqlite':
            self.engine.execute('PRAGMA synchronous = 0') # this significantly reduces disk IO on SQLite DB

    def chunk_exists(self, chunk):
        "Check if given chunk records already exist in the database"
        chunk_type_sub = (chunk.chunk_type == 'sub')
        q = select([func.count()]).where(
                (Chunk.chunk_number == chunk.chunk_number)
                & (Chunk.chunk_type_sub == chunk_type_sub)
                & (Chunk.list_name == chunk.list_name)
            )
        res = self.engine.execute(q)
        count = res.fetchone()[0]
        res.close()
        return count > 0

    @staticmethod
    def insert_chunk(connection, chunk):
        "Insert hash prefixes from the chunk to the database"
        q = Chunk.__table__.insert()
        data = {
            'chunk_number': chunk.chunk_number,
            'list_name': chunk.list_name,
            'chunk_type_sub': (chunk.chunk_type == 'sub')
        }
        connection.execute(q, data)

    def store_chunk(self, chunk):
        "Store chunk in the database"
        log.debug('Storing %s chunk #%s for list name %s' % (chunk.chunk_type, chunk.chunk_number, chunk.list_name))
        with self.engine.begin() as connection:
            self.insert_chunk(connection, chunk)
            q = HashPrefix.__table__.insert()
            current_timestamp = now()
            data = [
                {
                    'list_name': chunk.list_name,
                    'chunk_number': chunk.chunk_number,
                    'chunk_type_sub': (chunk.chunk_type == 'sub'),
                    'value': hash_value,
                    'timestamp': current_timestamp,
                    'full_hash_expires_at': current_timestamp,
                }
                for hash_value in chunk.hashes
            ]
            if not data:
                return
            try:
                connection.execute(q, data)
            except IntegrityError as e:
                log.warn('Failed to insert chunk because of %s' % e)

    def cleanup_expired_hashes(self):
        "Delete all hashes that behind their expiration date"
        with self.engine.begin() as connection:
            q = FullHash.__table__.delete().where(FullHash.expires_at < now())
            connection.execute(q)

    def store_full_hashes(self, hash_prefix, hashes):
        "Store hashes found for the given hash prefix"
        self.cleanup_expired_hashes()
        current_timestamp = now()
        expires_at = current_timestamp + datetime.timedelta(seconds=hashes['cache_lifetime'])
        with self.engine.begin() as connection:
            q = FullHash.__table__.insert()
            for list_name, hash_values in hashes['hashes'].items():
                for hash_value in hash_values:
                    data = {
                        'value': hash_value,
                        'list_name': list_name,
                        'downloaded_at': current_timestamp,
                        'expires_at': expires_at,
                    }
                    connection.execute(q, data)
            q = HashPrefix.update().where((chunk_type_sub == False) & (value == hash_prefix))
            data = {
                'full_hash_expires_at': expires_at
            }
            connection.execute(q, data)

    def full_hash_sync_required(self, hash_prefix):
        """Check if hashes for the given hash prefix have expired

        and that prefix needs to be re-queried
        """
        q = select([func.count()]).where(
            (HashPrefix.full_hash_expires_at > now()) \
            & (HashPrefix.chunk_type_sub == False) \
            & (HashPrefix.value == hash_prefix)
        )
        res = self.engine.execute(q)
        count = res.fetchone()[0]
        res.close()
        return count == 0

    def lookup_full_hash(self, hash_value):
        "Query DB to see if hash is blacklisted"
        q = select([FullHash.list_name]).where(FullHash.value == hash_value)
        res = self.engine.execute(q)
        return [h[0] for h in res.fetchall()]

    def lookup_hash_prefix(self, hash_prefix):
        """Check if hash prefix is in the list and does not have 'sub'
        status signifying that it should be evicted from the blacklist
        """
        q_add = select([HashPrefix.list_name]).where((HashPrefix.chunk_type_sub == False) & (HashPrefix.value == hash_prefix))
        q_sub = select([HashPrefix.list_name]).where((HashPrefix.chunk_type_sub == True) & (HashPrefix.value == hash_prefix))

        res = self.engine.execute(q_add)
        lists_add = [r[0] for r in res.fetchall()]
        if len(lists_add) == 0:
            return False
        res = self.engine.execute(q_sub)
        lists_sub = [r[0] for r in res.fetchall()]
        if len(lists_sub) == 0:
            return True
        if set(lists_add) - set(lists_sub):
            return True
        return False

    def del_add_chunks(self, chunk_numbers):
        "Delete records associated with 'add' chunk"
        if not chunk_numbers:
            return
        log.info('Deleting "add" chunks %s' % repr(chunk_numbers))
        with self.engine.begin() as connection:
            for cn in self.expand_ranges(chunk_numbers):
                q = Chunk.__table__.delete().where((Chunk.chunk_type_sub == False) & (Chunk.chunk_number == cn))
                connection.execute(q)

    def del_sub_chunks(self, chunk_numbers):
        "Delete records associated with 'sub' chunk"
        if not chunk_numbers:
            return
        log.info('Deleting "sub" chunks %s' % repr(chunk_numbers))
        with self.engine.begin() as connection:
            for cn in self.expand_ranges(chunk_numbers):
                q = Chunk.__table__.delete().where((Chunk.chunk_type_sub == True) & (Chunk.chunk_number == cn))
                connection.execute(q)

    def get_list_names(self):
        "Get names for known lists in the cache."
        q = select([Chunk.list_name]).group_by(Chunk.list_name)
        res = self.engine.execute(q)
        return [l[0] for l in res.fetchall()]

    def get_existing_chunks(self):
        "Get the list of chunks that are available in the local cache"
        output = {}
        for chunk_type_sub in (False, True):
            for list_name in self.get_list_names():
                q = select([Chunk.chunk_number]).where((Chunk.chunk_type_sub == chunk_type_sub) & (Chunk.list_name == list_name))
                res = self.engine.execute(q)
                chunks = [int(c[0]) for c in res.fetchall()]
                if chunks:
                    if not output.has_key(list_name):
                        output[list_name] = {}
                    output[list_name][(chunk_type_sub and 'sub' or 'add')] = self.compress_ranges(chunks)
        return output

    def total_cleanup(self):
        "Reset local cache"
        with self.engine.begin() as connection:
            q = FullPrefix.__table__.delete()
            connection.execute(q)
            q = HashPrefix.__table__.delete()
            connection.execute(q)
            q = Chunk.__table__.delete()
            connection.execute(q)
