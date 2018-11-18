#!/usr/bin/env python

from base64 import b64decode

import logging

from gglsbl.utils import to_hex
from gglsbl.protocol import SafeBrowsingApiClient, URL
from gglsbl.storage import SqliteStorage, ThreatList, HashPrefixList


log = logging.getLogger('gglsbl')
log.addHandler(logging.NullHandler())


class SafeBrowsingList(object):
    """Interface for Google Safe Browsing API

    supporting partial update of the local cache.
    https://developers.google.com/safe-browsing/v4/
    """

    def __init__(self, api_key, db_path='/tmp/gsb_v4.db',
                 discard_fair_use_policy=False, platforms=None, timeout=10):
        """Constructor.

        Args:
            api_key: string, a key for API authentication.
            db_path: string, path to SQLite DB file to store cached data.
            discard_fair_use_policy: boolean, disable request frequency throttling (only for testing).
            platforms: list, threat lists to look up, default includes all platforms.
            timeout: seconds to wait for Sqlite DB to become unlocked from concurrent WRITE transaction.
        """
        self.api_client = SafeBrowsingApiClient(api_key, discard_fair_use_policy=discard_fair_use_policy)
        self.storage = SqliteStorage(db_path, timeout=timeout)
        self.platforms = platforms

    def _verify_threat_list_checksum(self, threat_list, remote_checksum):
        local_checksum = self.storage.hash_prefix_list_checksum(threat_list)
        return remote_checksum == local_checksum

    def update_hash_prefix_cache(self):
        """Update locally cached threat lists."""
        try:
            self.storage.cleanup_full_hashes()
            self.storage.commit()
            self._sync_threat_lists()
            self.storage.commit()
            self._sync_hash_prefix_cache()
        except Exception:
            self.storage.rollback()
            raise

    def _sync_threat_lists(self):
        self.api_client.fair_use_delay()
        threat_lists_to_remove = dict()
        for ts in self.storage.get_threat_lists():
            threat_lists_to_remove[repr(ts)] = ts
        threat_lists = self.api_client.get_threats_lists()
        for entry in threat_lists:
            threat_list = ThreatList.from_api_entry(entry)
            if self.platforms is None or threat_list.platform_type in self.platforms:
                self.storage.add_threat_list(threat_list)
                try:
                    del threat_lists_to_remove[repr(threat_list)]
                except KeyError:
                    pass
        for ts in threat_lists_to_remove.values():
            self.storage.delete_hash_prefix_list(ts)
            self.storage.delete_threat_list(ts)
        del threat_lists_to_remove

    def _sync_hash_prefix_cache(self):
        self.api_client.fair_use_delay()
        client_state = self.storage.get_client_state()
        for response in self.api_client.get_threats_update(client_state):
            response_threat_list = ThreatList(response['threatType'], response['platformType'],
                                              response['threatEntryType'])
            if response['responseType'] == 'FULL_UPDATE':
                self.storage.delete_hash_prefix_list(response_threat_list)
            for r in response.get('removals', []):
                self.storage.remove_hash_prefix_indices(response_threat_list, r['rawIndices']['indices'])
            for a in response.get('additions', []):
                hash_prefix_list = HashPrefixList(a['rawHashes']['prefixSize'], b64decode(a['rawHashes']['rawHashes']))
                self.storage.populate_hash_prefix_list(response_threat_list, hash_prefix_list)
            expected_checksum = b64decode(response['checksum']['sha256'])
            log.info('Verifying threat hash prefix list checksum')
            if self._verify_threat_list_checksum(response_threat_list, expected_checksum):
                log.info('Local cache checksum matches the server: {}'.format(to_hex(expected_checksum)))
                self.storage.update_threat_list_client_state(response_threat_list, response['newClientState'])
                self.storage.commit()
            else:
                raise Exception('Local cache checksum does not match the server: '
                                '"{}". Consider removing {}'.format(to_hex(expected_checksum), self.storage.db_path))

    def _sync_full_hashes(self, hash_prefixes):
        """Download full hashes matching hash_prefixes.

        Also update cache expiration timestamps.
        """
        client_state = self.storage.get_client_state()
        self.api_client.fair_use_delay()
        fh_response = self.api_client.get_full_hashes(hash_prefixes, client_state)

        # update negative cache for each hash prefix
        # store full hash (insert or update) with positive cache bumped up
        for m in fh_response.get('matches', []):
            threat_list = ThreatList(m['threatType'], m['platformType'], m['threatEntryType'])
            hash_value = b64decode(m['threat']['hash'])
            cache_duration = int(m['cacheDuration'].rstrip('s'))
            malware_threat_type = None
            for metadata in m['threatEntryMetadata'].get('entries', []):
                k = b64decode(metadata['key'])
                v = b64decode(metadata['value'])
                if k == 'malware_threat_type':
                    malware_threat_type = v
            self.storage.store_full_hash(threat_list, hash_value, cache_duration, malware_threat_type)

        negative_cache_duration = int(fh_response['negativeCacheDuration'].rstrip('s'))
        for prefix_value in hash_prefixes:
            self.storage.update_hash_prefix_expiration(prefix_value, negative_cache_duration)

    def lookup_url(self, url):
        """Look up specified URL in Safe Browsing threat lists."""
        if type(url) is not str:
            url = url.encode('utf8')
        if not url.strip():
            raise ValueError("Empty input string.")
        url_hashes = URL(url).hashes
        try:
            list_names = self._lookup_hashes(url_hashes)
            self.storage.commit()
        except Exception:
            self.storage.rollback()
            raise
        if list_names:
            return list_names
        return None

    def _lookup_hashes(self, full_hashes):
        """Lookup URL hash in blacklists

        Returns names of lists it was found in.
        """
        full_hashes = list(full_hashes)
        cues = [fh[0:4] for fh in full_hashes]
        result = []
        matching_prefixes = {}
        matching_full_hashes = set()
        is_potential_threat = False
        # First lookup hash prefixes which match full URL hash
        for (hash_prefix, negative_cache_expired) in self.storage.lookup_hash_prefix(cues):
            for full_hash in full_hashes:
                if full_hash.startswith(hash_prefix):
                    is_potential_threat = True
                    # consider hash prefix negative cache as expired if it is expired in at least one threat list
                    matching_prefixes[hash_prefix] = matching_prefixes.get(hash_prefix, False) or negative_cache_expired
                    matching_full_hashes.add(full_hash)
        # if none matches, URL hash is clear
        if not is_potential_threat:
            return []
        # if there is non-expired full hash, URL is blacklisted
        matching_expired_threat_lists = set()
        for threat_list, has_expired in self.storage.lookup_full_hashes(matching_full_hashes):
            if has_expired:
                matching_expired_threat_lists.add(threat_list)
            else:
                result.append(threat_list)
        if result:
            return result

        # If there are no matching expired full hash entries
        # and negative cache is still current for all prefixes, consider it safe
        if len(matching_expired_threat_lists) == 0 and sum(map(int, matching_prefixes.values())) == 0:
            log.info('Negative cache hit.')
            return []

        # Now we can assume that there are expired matching full hash entries and/or
        # cache prefix entries with expired negative cache. Both require full hash sync.
        self._sync_full_hashes(matching_prefixes.keys())
        # Now repeat full hash lookup
        for threat_list, has_expired in self.storage.lookup_full_hashes(matching_full_hashes):
            if not has_expired:
                result.append(threat_list)
        return result
