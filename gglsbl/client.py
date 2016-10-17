#!/usr/bin/env python

import logging
log = logging.getLogger()
log.addHandler(logging.NullHandler())

from .protocol import PrefixListProtocolClient, FullHashProtocolClient, URL
from .storage import SqlAlchemyStorage, SqliteStorage


class SafeBrowsingList(object):
    """Interface for Google Safe Browsing API

    supporting partial update of the local cache.
    https://developers.google.com/safe-browsing/developers_guide_v3
    sqlite://user:password@db_host:port/db_name
    """
    def __init__(self, api_key, db_path='/tmp/gsb_v3.db', discard_fair_use_policy=False):
        self.prefixListProtocolClient = PrefixListProtocolClient(api_key,
                                discard_fair_use_policy=discard_fair_use_policy)
        self.fullHashProtocolClient = FullHashProtocolClient(api_key)
        if ':' in db_path:
            log.info('Using SqlAlchemy storage backend')
            self.storage = SqlAlchemyStorage(db_path)
        else:
            log.info('Using Sqlite storage backend')
            self.storage = SqliteStorage(db_path)

    def update_hash_prefix_cache(self):
        "Sync locally stored hash prefixes with remote server"
        existing_chunks = self.storage.get_existing_chunks()
        response = self.prefixListProtocolClient.retrieveMissingChunks(existing_chunks=existing_chunks)
        if response.reset_required:
            self.storage.total_cleanup()

        for chunk_type, v in response.del_chunks.items():
            for list_name, chunk_numbers in v.items():
                self.storage.del_chunks(chunk_type, list_name, chunk_numbers)
        for chunk in response.chunks:
            if self.storage.chunk_exists(chunk):
                log.debug('chunk #%d of type %s exists in stored list %s, skipping',
                    chunk.chunk_number, chunk.chunk_type, chunk.list_name)
                continue
            self.storage.store_chunk(chunk)

    def sync_full_hashes(self, hash_prefix):
        "Sync full hashes starting with hash_prefix from remote server"
        if not self.storage.full_hash_sync_required(hash_prefix):
            log.debug('Cached full hash entries are still valid for "0x%s", no sync required.', hash_prefix.encode("hex"))
            return
        full_hashes = self.fullHashProtocolClient.getHashes([hash_prefix])
        if not full_hashes:
            return
        self.storage.store_full_hashes(hash_prefix, full_hashes)

    def lookup_url(self, url):
        "Look up URL in Safe Browsing blacklists"
        url_hashes = URL(url).hashes
        for url_hash in url_hashes:
            list_name = self.lookup_hash(url_hash)
            if list_name:
                return list_name
        return None

    def lookup_hash(self, full_hash):
        """Lookup URL hash in blacklists

        Returns names of lists it was found in.
        """
        hash_prefix = full_hash[0:4]
        if self.storage.lookup_hash_prefix(hash_prefix):
            self.sync_full_hashes(hash_prefix)
            return self.storage.lookup_full_hash(full_hash)
