
import binascii
import sys


def to_hex_2(v):
    return v.encode("hex")


def to_hex_3(v):
    return binascii.hexlify(v)


global to_hex


if (sys.version_info > (3, 0)):
    to_hex = to_hex_3
else:
    to_hex = to_hex_2
