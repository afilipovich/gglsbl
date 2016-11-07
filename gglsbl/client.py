#!/usr/bin/env python

from base64 import b64encode, b64decode

import logging
log = logging.getLogger()
log.addHandler(logging.NullHandler())

from gglsbl.protocol import SafeBrowsingApiClient, URL
from gglsbl.storage import SqliteStorage, ThreatList, HashPrefixList


class SafeBrowsingList(object):
    """Interface for Google Safe Browsing API

    supporting partial update of the local cache.
    https://developers.google.com/safe-browsing/developers_guide_v3
    """
    def __init__(self, api_key, db_path='/tmp/gsb_v3.db', discard_fair_use_policy=False):
        self.api_client = SafeBrowsingApiClient(api_key)
        self.storage = SqliteStorage(db_path)

    def verify_threat_list_checksum(self, threat_list, remote_checksum):
        local_checksum = self.storage.hash_prefix_list_checksum(threat_list)
        return remote_checksum == local_checksum

    def update_hash_prefix_cache(self):
        threat_lists = self.api_client.get_threats_lists()
        for entry in threat_lists:
            threat_list = ThreatList.from_api_entry(entry)
            self.storage.add_threat_list(threat_list)

        for threat_list, client_state in self.storage.get_threat_lists():
            for response in self.api_client.get_threats_update(client_state, threat_list):
                response_threat_list = ThreatList(response['threatType'], response['platformType'], response['threatEntryType'])
                if response['responseType'] == 'FULL_UPDATE':
                    self.storage.delete_hash_prefix_list(response_threat_list)
                for a in response.get('additions', []):
                    hash_prefix_list = HashPrefixList(a['rawHashes']['prefixSize'], b64decode(a['rawHashes']['rawHashes']))
                    self.storage.add_hash_prefix_list(response_threat_list, hash_prefix_list)
                for r in response.get('removals', []):
                    self.storage.remove_hash_prefix_indices(response_threat_list, r['rawIndices']['indices'])
                self.storage.update_threat_list_client_state(response_threat_list, response['newClientState'])



            expected_checksum = b64decode(response['checksum']['sha256'])
            if self.verify_threat_list_checksum(response_threat_list, expected_checksum):
                log.info('Local cache checksum matches the server: {}'.format(expected_checksum.encode('hex')))
            else:
                raise Exception('Local cache checksum does not match the server: "{}"'.format(expected_checksum.encode('hex')))
            break # temp for debug


    def ___update_hash_prefix_cache(self):
        "Sync locally stored hash prefixes with remote server"
        existing_chunks = self.storage.get_existing_chunks()
        response = self.prefixListProtocolClient.retrieveMissingChunks(existing_chunks=existing_chunks)
        if response.reset_required:
            self.storage.total_cleanup()
        try:
            for chunk_type, v in response.del_chunks.items():
                for list_name, chunk_numbers in v.items():
                    self.storage.del_chunks(chunk_type, list_name, chunk_numbers)
            for chunk in response.chunks:
                if self.storage.chunk_exists(chunk):
                    log.debug('chunk #%d of type %s exists in stored list %s, skipping',
                        chunk.chunk_number, chunk.chunk_type, chunk.list_name)
                    continue
                self.storage.store_chunk(chunk)
        except:
            self.storage.db.rollback()
            raise

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
        try:
            if self.storage.lookup_hash_prefix(hash_prefix):
                self.sync_full_hashes(hash_prefix)
                return self.storage.lookup_full_hash(full_hash)
        except:
            self.storage.db.rollback()
            raise

