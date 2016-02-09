#!/usr/bin/env python

import os
import sqlite3

import logging
log = logging.getLogger()
log.addHandler(logging.NullHandler())


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

