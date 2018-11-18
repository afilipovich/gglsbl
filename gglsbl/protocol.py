#!/usr/bin/env python

import sys
from functools import wraps

try:
    import urllib
    import urlparse
except ImportError:
    import urllib.parse as urllib
    from urllib import parse as urlparse

import struct
import time
import posixpath
import re
import hashlib
import socket
import random
from base64 import b64encode

try:
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    from apiclient.discovery import build
    from apiclient.errors import HttpError

import logging
from ._version import get_versions


__version__ = get_versions()['version']
del get_versions

log = logging.getLogger('gglsbl')
log.addHandler(logging.NullHandler())


_fail_count = 0


def autoretry(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _fail_count
        while True:
            try:
                r = func(*args, **kwargs)
                _fail_count = 0
                return r
            except HttpError as e:
                if not (hasattr(e, 'resp') and 'status' in e.resp
                        and e.resp['status'].isdigit and int(e.resp['status']) >= 500):
                    raise  # we do not want to retry auth errors etc.
                _fail_count += 1
                wait_for = min(2 ** (_fail_count - 1) * 15 * 60 * (1 + random.random()), 24 * 60 * 60)
                log.exception('Call Failed for %s time(s). Retrying in %s seconds: %s',
                              _fail_count, wait_for, str(e))
                time.sleep(wait_for)
            except socket.error:
                transient_error_wait = 2
                log.exception('Socket error, retrying in {} seconds.'.format(transient_error_wait))
                time.sleep(transient_error_wait)
    return wrapper


class SafeBrowsingApiClient(object):
    def __init__(self, developer_key, client_id='python-gglsbl',
                 client_version=__version__, discard_fair_use_policy=True):
        """Constructor.

        :param developer_key: Google API key
        :param discard_fair_use_policy: do not wait between individual API calls as requested by the spec
        """
        self.client_id = client_id
        self.client_version = client_version
        self.discard_fair_use_policy = discard_fair_use_policy
        if self.discard_fair_use_policy:
            log.warn('Circumventing request frequency throttling is against Safe Browsing API policy.')
        self.service = build('safebrowsing', 'v4', developerKey=developer_key, cache_discovery=False)
        self.next_request_no_sooner_than = None

    def set_wait_duration(self, minimum_wait_duration):
        if self.discard_fair_use_policy:
            return
        if minimum_wait_duration is None:
            self.next_request_no_sooner_than = None
            return
        self.next_request_no_sooner_than = time.time() + float(minimum_wait_duration.rstrip('s'))

    def fair_use_delay(self):
        if self.next_request_no_sooner_than is not None:
            sleep_for = max(0, self.next_request_no_sooner_than - time.time())
            log.info('Sleeping for {} seconds until next request.'.format(sleep_for))
            time.sleep(sleep_for)

    @autoretry
    def get_threats_lists(self):
        """Retrieve all available threat lists"""
        response = self.service.threatLists().list().execute()
        self.set_wait_duration(response.get('minimumWaitDuration'))
        return response['threatLists']

    @autoretry
    def get_threats_update(self, client_state):
        """Fetch hash prefixes update for given threat list.

        client_state is a dict which looks like {(threatType, platformType, threatEntryType): clientState}
        """
        request_body = {
            "client": {
                "clientId": self.client_id,
                "clientVersion": self.client_version,
            },
            "listUpdateRequests": [],
        }
        for (threat_type, platform_type, threat_entry_type), current_state in client_state.items():
            request_body['listUpdateRequests'].append(
                {
                    "threatType": threat_type,
                    "platformType": platform_type,
                    "threatEntryType": threat_entry_type,
                    "state": current_state,
                    "constraints": {
                        "supportedCompressions": ["RAW"]
                    }
                }
            )
        response = self.service.threatListUpdates().fetch(body=request_body).execute()
        self.set_wait_duration(response.get('minimumWaitDuration'))
        return response['listUpdateResponses']

    @autoretry
    def get_full_hashes(self, prefixes, client_state):
        """Find full hashes matching hash prefixes.

        client_state is a dict which looks like {(threatType, platformType, threatEntryType): clientState}
        """
        request_body = {
            "client": {
                "clientId": self.client_id,
                "clientVersion": self.client_version,
            },
            "clientStates": [],
            "threatInfo": {
                "threatTypes": [],
                "platformTypes": [],
                "threatEntryTypes": [],
                "threatEntries": [],
            }
        }
        for prefix in prefixes:
            request_body['threatInfo']['threatEntries'].append({"hash": b64encode(prefix).decode()})
        for ((threatType, platformType, threatEntryType), clientState) in client_state.items():
            request_body['clientStates'].append(clientState)
            if threatType not in request_body['threatInfo']['threatTypes']:
                request_body['threatInfo']['threatTypes'].append(threatType)
            if platformType not in request_body['threatInfo']['platformTypes']:
                request_body['threatInfo']['platformTypes'].append(platformType)
            if threatEntryType not in request_body['threatInfo']['threatEntryTypes']:
                request_body['threatInfo']['threatEntryTypes'].append(threatEntryType)
        response = self.service.fullHashes().find(body=request_body).execute()
        self.set_wait_duration(response.get('minimumWaitDuration'))
        return response


class URL(object):
    """URL representation suitable for lookup"""

    __py3 = (sys.version_info > (3, 0))

    def __init__(self, url):
        """Constructor.

        :param url: can be either of str or bytes type.
        """
        if self.__py3:
            if type(url) is bytes:
                self.url = bytes(url)
            else:
                self.url = url.encode()
        else:
            self.url = str(url)

    @property
    def hashes(self):
        """Hashes of all possible permutations of the URL in canonical form"""
        for url_variant in self.url_permutations(self.canonical):
            url_hash = self.digest(url_variant)
            yield url_hash

    @property
    def canonical(self):
        """Convert URL to its canonical form."""
        def full_unescape(u):
            uu = urllib.unquote(u)
            if uu == u:
                return uu
            else:
                return full_unescape(uu)

        def full_unescape_to_bytes(u):
            uu = urlparse.unquote_to_bytes(u)
            if uu == u:
                return uu
            else:
                return full_unescape_to_bytes(uu)

        def quote(s):
            safe_chars = '!"$&\'()*+,-./:;<=>?@[\\]^_`{|}~'
            return urllib.quote(s, safe=safe_chars)

        url = self.url.strip()
        url = url.replace(b'\n', b'').replace(b'\r', b'').replace(b'\t', b'')
        url = url.split(b'#', 1)[0]
        if url.startswith(b'//'):
            url = b'http:' + url
        if len(url.split(b'://')) <= 1:
            url = b'http://' + url
        # at python3 work with bytes instead of string
        # as URL may contain invalid unicode characters
        if self.__py3 and type(url) is bytes:
            url = quote(full_unescape_to_bytes(url))
        else:
            url = quote(full_unescape(url))
        url_parts = urlparse.urlsplit(url)
        if not url_parts[0]:
            url = 'http://{}'.format(url)
            url_parts = urlparse.urlsplit(url)
        protocol = url_parts.scheme
        if self.__py3:
            host = full_unescape_to_bytes(url_parts.hostname)
            path = full_unescape_to_bytes(url_parts.path)
        else:
            host = full_unescape(url_parts.hostname)
            path = full_unescape(url_parts.path)
        query = url_parts.query
        if not query and '?' not in url:
            query = None
        if not path:
            path = b'/'
        has_trailing_slash = (path[-1:] == b'/')
        path = posixpath.normpath(path).replace(b'//', b'/')
        if has_trailing_slash and path[-1:] != b'/':
            path = path + b'/'
        port = url_parts.port
        host = host.strip(b'.')
        host = re.sub(br'\.+', b'.', host).lower()
        if host.isdigit():
            try:
                host = socket.inet_ntoa(struct.pack("!I", int(host)))
            except Exception:
                pass
        elif host.startswith(b'0x') and b'.' not in host:
            try:
                host = socket.inet_ntoa(struct.pack("!I", int(host, 16)))
            except Exception:
                pass
        quoted_path = quote(path)
        quoted_host = quote(host)
        if port is not None:
            quoted_host = '{}:{}'.format(quoted_host, port)
        canonical_url = '{}://{}{}'.format(protocol, quoted_host, quoted_path)
        if query is not None:
            canonical_url = '{}?{}'.format(canonical_url, query)
        return canonical_url

    @staticmethod
    def url_permutations(url):
        """Try all permutations of hostname and path which can be applied

        to blacklisted URLs
        """
        def url_host_permutations(host):
            if re.match(r'\d+\.\d+\.\d+\.\d+', host):
                yield host
                return
            parts = host.split('.')
            l = min(len(parts), 5)
            if l > 4:
                yield host
            for i in range(l - 1):
                yield '.'.join(parts[i - l:])

        def url_path_permutations(path):
            yield path
            query = None
            if '?' in path:
                path, query = path.split('?', 1)
            if query is not None:
                yield path
            path_parts = path.split('/')[0:-1]
            curr_path = ''
            for i in range(min(4, len(path_parts))):
                curr_path = curr_path + path_parts[i] + '/'
                yield curr_path

        protocol, address_str = urllib.splittype(url)
        host, path = urllib.splithost(address_str)
        user, host = urllib.splituser(host)
        host, port = urllib.splitport(host)
        host = host.strip('/')
        seen_permutations = set()
        for h in url_host_permutations(host):
            for p in url_path_permutations(path):
                u = '{}{}'.format(h, p)
                if u not in seen_permutations:
                    yield u
                    seen_permutations.add(u)

    @staticmethod
    def digest(url):
        """Hash the URL"""
        return hashlib.sha256(url.encode('utf-8')).digest()


if __name__ == '__main__':
    from pprint import pprint
    c = SafeBrowsingApiClient('AIzaSyATpqLltciaMve61Wywb5yNDA8D8BvXEn4')
    r = c.get_threats_lists()
    pprint(r)
