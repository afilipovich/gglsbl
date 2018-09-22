
import sys
import codecs

def to_hex_2(v):
    return v.encode("hex")

def to_hex_34(v):
    return codecs.encode(v, "hex").decode("utf8")

def to_hex_35(v):
    return v.hex()

global to_hex

version = sys.version_info
if (version > (3, 0)):
    to_hex = to_hex_34
elif (version > (3, 4)):
    to_hex = to_hex_35
else:
    to_hex = to_hex_2
