import datetime
import secrets
import hashlib
import base64
import time
import hmac
import sys
import os

# convert integer to the OATH specified bytestring
def int_to_bytestring(i):
    result = []
    while i != 0:
        result.append(chr(i & 0xFF))
        i = i >> 8
    return ''.join(reversed(result)).rjust(8, '\0')


def generate_secret():
    be32 = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
    ret = ''

    for i in range(0, 16):
        ret += secrets.choice(be32)

    return ret


# This implementation is derived from PyOTP project
def generate_totp(secret):
    """
            @param [Integer] input the number used seed the HMAC
            Usually either the counter, or the computed integer
            based on the Unix timestamp
    """
    timestamp = datetime.datetime.now()

    i = int((time.mktime(timestamp.timetuple())) / 30)
    result = []

    while i != 0:
        result.append(chr(i & 0xFF))
        i = i >> 8

    OATHbytestring = ''.join(reversed(result)).rjust(8, '\0')
    base = base64.b32decode(secret, casefold=True)
    hmac_hash = hmac.new(base, OATHbytestring.encode('latin-1'), hashlib.sha1).digest()

    offset = hmac_hash[19] & 0xf
    code = (hmac_hash[offset] & 0x7f) << 24 | (hmac_hash[offset + 1] & 0xff) << 16 | (
            hmac_hash[offset + 2] & 0xff) << 8 | (hmac_hash[offset + 3] & 0xff)

    code_6 = code % 10 ** 6
    # fill any preceding 0
    code_6 = str(code_6).zfill(6)

    return code_6


if __name__ == '__main__':
    # testing
    generate_totp("XMKLMBPBWBSYK5FJ")
