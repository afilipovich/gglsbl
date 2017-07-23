#!/usr/bin/env python

"""Keeps local Google Safe Browsing cache in sync.

Accessing Google Safe Browsing API requires API key, you can find
more info on getting it here:
https://developers.google.com/safe-browsing/lookup_guide#GettingStarted

"""

import argparse
import json
import sys
import time

from gglsbl import SafeBrowsingList

import logging
log = logging.getLogger('gglsbl')
log.setLevel(logging.DEBUG)


def setupArgsParser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api-key',
                default=None,
                required=True,
                help='Safe Browsing API key [REQUIRED]')
    parser.add_argument('--db-path',
                default='/tmp/gsb_v4.db',
                help='Path to SQLite DB')
    parser.add_argument('--redis-host',
                default=None,
                help='Use redis as additional common cache.')
    parser.add_argument('--log',
                default=None,
                help='Path to log file, by default log to STDERR')
    parser.add_argument('--check-url',
                default=None,
                help='Check if URL is in black list and exit')
    parser.add_argument('--redis-only',
                default=False,
                action = 'store_true',
                help='Use only Redis cache (works only for lookups, not cache sync).')
    parser.add_argument('--debug',
                default=False,
                action = 'store_true',
                help='Show debug output')
    parser.add_argument('--onetime',
                default=False,
                action = 'store_true',
                help='Run blacklists sync only once with reduced delays')
    return parser

def setupLogger(log_file, debug):
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    lh = log_file is None and logging.StreamHandler() or logging.FileHandler(log_file)
    lh.setLevel(debug and logging.DEBUG or logging.INFO)
    lh.setFormatter(formatter)
    log = logging.getLogger('gglsbl')
    log.addHandler(lh)

def run_sync(sbl):
    try:
        sbl.update_hash_prefix_cache()
    except (KeyboardInterrupt, SystemExit):
        log.info('Shutting down')
        sys.exit(0)
    except:
        log.exception('Failed to synchronize with GSB service')
        time.sleep(3)

def main():
    args_parser = setupArgsParser()
    args = args_parser.parse_args()
    setupLogger(args.log, args.debug)
    db_path = args.db_path
    if args.redis_only:
        db_path = None
    if args.check_url:
        sbl = SafeBrowsingList(args.api_key, db_path=db_path, redis_host=args.redis_host)
        bl = sbl.lookup_url(args.check_url)
        if bl is None:
            print('{} is not blacklisted'.format(args.check_url))
        else:
            print('{} is blacklisted in {}'.format(args.check_url, bl))
        sys.exit(0)
    if args.onetime:
        sbl = SafeBrowsingList(args.api_key, db_path=db_path, redis_host=args.redis_host, discard_fair_use_policy=True)
        run_sync(sbl)
    else:
        sbl = SafeBrowsingList(args.api_key, db_path=db_path, redis_host=args.redis_host)
        while True:
            run_sync(sbl)

if __name__ == '__main__':
    main()

