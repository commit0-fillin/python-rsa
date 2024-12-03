"""Functions for generating random numbers."""
import os
from rsa import common, transform

def read_random_bits(nbits: int) -> bytes:
    """Reads 'nbits' random bits.

    If nbits isn't a whole number of bytes, an extra byte will be appended with
    only the lower bits set.
    """
    nbytes, rbits = divmod(nbits, 8)

    # Get the whole bytes
    bytes_data = os.urandom(nbytes)

    # If there are remaining bits, add one more byte
    if rbits > 0:
        last_byte = os.urandom(1)[0] & ((1 << rbits) - 1)
        bytes_data += bytes([last_byte])

    return bytes_data

def read_random_int(nbits: int) -> int:
    """Reads a random integer of approximately nbits bits."""
    return transform.bytes2int(read_random_bits(nbits))

def read_random_odd_int(nbits: int) -> int:
    """Reads a random odd integer of approximately nbits bits.

    >>> read_random_odd_int(512) & 1
    1
    """
    return read_random_int(nbits) | 1

def randint(maxvalue: int) -> int:
    """Returns a random integer x with 1 <= x <= maxvalue

    May take a very long time in specific situations. If maxvalue needs N bits
    to store, the closer maxvalue is to (2 ** N) - 1, the faster this function
    is.
    """
    bit_size = common.bit_size(maxvalue)
    
    while True:
        value = read_random_int(bit_size)
        if 1 <= value <= maxvalue:
            return value
