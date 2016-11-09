#!/usr/bin/env python

import urllib, urlparse
import struct
import time
import posixpath
import re
import hashlib
import socket
from base64 import b64encode, b64decode

from googleapiclient.discovery import build

import logging
log = logging.getLogger()
log.addHandler(logging.NullHandler())

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions


class SafeBrowsingApiClient(object):
    def __init__(self, developerKey, clientId='gglsbl', clientVersion=__version__):
        self.clientId = clientId
        self.clientVersion = clientVersion
        self.service = build('safebrowsing', 'v4', developerKey=developerKey)

    def get_threats_lists(self):
        """Retrieve all available threat lists
        """
        response = self.service.threatLists().list().execute()
        return response['threatLists']

    def get_threats_update(self, current_state, threat_list):
        """Fetch hash prefixes update for given threat list
        """
        request_body = {
                "client": {
                "clientId":       self.clientId,
                "clientVersion":  self.clientVersion,
            },
            "listUpdateRequests": [{
                "threatType":      threat_list.threat_type,
                "platformType":    threat_list.platform_type,
                "threatEntryType": threat_list.threat_entry_type,
                "state":           current_state,
                "constraints": {
                    "supportedCompressions": ["RAW"]
                }
            }]
        }
        response = self.service.threatListUpdates().fetch(body=request_body).execute()
        return response['listUpdateResponses']

    def get_full_hashes(self, prefixes, client_state):
        """Find full hashes matching hash prefixes.

        client_state is a dict which looks like {(threatType, platformType, threatEntryType): clientState}
        """
        request_body = {
          "client": {
            "clientId":      self.clientId,
            "clientVersion": self.clientVersion,
          },
          "clientStates": [],
          "threatInfo": {
            "threatTypes":      [],
            "platformTypes":    [],
            "threatEntryTypes": [],
            "threatEntries": [],
          }
        }
        for prefix in prefixes:
            request_body['threatInfo']['threatEntries'].append({"hash": b64encode(prefix)})
        for ((threatType, platformType, threatEntryType), clientState) in client_state.items():
            request_body['clientStates'].append(clientState)
            if threatType not in request_body['threatInfo']['threatTypes']:
                request_body['threatInfo']['threatTypes'].append(threatType)
            if platformType not in request_body['threatInfo']['platformTypes']:
                request_body['threatInfo']['platformTypes'].append(platformType)
            if threatEntryType not in request_body['threatInfo']['threatEntryTypes']:
                request_body['threatInfo']['threatEntryTypes'].append(threatEntryType)
        response = self.service.fullHashes().find(body=request_body).execute()
        return response


class URL(object):
    "URL representation suitable for lookup"
    def __init__(self, url):
        self.url = str(url)

    @property
    def hashes(self):
        "Hashes of all possible permutations of the URL in canonical form"
        for url_variant in self.url_permutations(self.canonical):
            url_hash = self.digest(url_variant)
            yield url_hash

    @property
    def canonical(self):
        "Convert URL to its canonical form"
        def full_unescape(u):
            uu = urllib.unquote(u)
            if uu == u:
                return uu
            else:
                return full_unescape(uu)
        def quote(s):
            safe_chars = '!"$&\'()*+,-./:;<=>?@[\\]^_`{|}~'
            return urllib.quote(s, safe=safe_chars)
        url = self.url.strip()
        url = url.replace('\n', '').replace('\r', '').replace('\t', '')
        url = url.split('#', 1)[0]
        url = quote(full_unescape(url))
        url_parts = urlparse.urlsplit(url)
        if not url_parts[0]:
            url = 'http://%s' % url
            url_parts = urlparse.urlsplit(url)
        protocol = url_parts.scheme
        host = full_unescape(url_parts.hostname)
        path = full_unescape(url_parts.path)
        query = url_parts.query
        if not query and '?' not in url:
            query = None
        if not path:
            path = '/'
        has_trailing_slash = (path[-1] == '/')
        path = posixpath.normpath(path).replace('//', '/')
        if has_trailing_slash and path[-1] != '/':
            path = path + '/'
        user = url_parts.username
        port = url_parts.port
        host = host.strip('.')
        host = re.sub(r'\.+', '.', host).lower()
        if host.isdigit():
            try:
                host = socket.inet_ntoa(struct.pack("!I", int(host)))
            except:
                pass
        if host.startswith('0x') and '.' not in host:
            try:
                host = socket.inet_ntoa(struct.pack("!I", int(host, 16)))
            except:
                pass
        quoted_path = quote(path)
        quoted_host = quote(host)
        if port is not None:
            quoted_host = '%s:%s' % (quoted_host, port)
        canonical_url = '%s://%s%s' % (protocol, quoted_host, quoted_path)
        if query is not None:
            canonical_url = '%s?%s' % (canonical_url, query)
        return canonical_url

    @staticmethod
    def url_permutations(url):
        """Try all permutations of hostname and path which can be applied
        to blacklisted URLs"""
        def url_host_permutations(host):
            if re.match(r'\d+\.\d+\.\d+\.\d+', host):
                yield host
                return
            parts = host.split('.')
            l = min(len(parts),5)
            if l > 4:
                yield host
            for i in xrange(l-1):
                yield '.'.join(parts[i-l:])
        def url_path_permutations(path):
            yield path
            query = None
            if '?' in path:
                path, query =  path.split('?', 1)
            if query is not None:
                yield path
            path_parts = path.split('/')[0:-1]
            curr_path = ''
            for i in xrange(min(4, len(path_parts) )):
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
                u = '%s%s' % (h, p)
                if u not in seen_permutations:
                    yield u
                    seen_permutations.add(u)

    @staticmethod
    def digest(url):
        "Hash the URL"
        return hashlib.sha256(url).digest()


if __name__ == '__main__':
    from pprint import pprint
    c = SafeBrowsingApiClient('AIzaSyATpqLltciaMve61Wywb5yNDA8D8BvXEn4')
    r = c.get_threats_lists()
    pprint(r)
