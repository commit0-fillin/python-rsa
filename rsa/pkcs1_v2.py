"""Functions for PKCS#1 version 2 encryption and signing

This module implements certain functionality from PKCS#1 version 2. Main
documentation is RFC 2437: https://tools.ietf.org/html/rfc2437
"""
from rsa import common, pkcs1, transform

def mgf1(seed: bytes, length: int, hasher: str='SHA-1') -> bytes:
    """
    MGF1 is a Mask Generation Function based on a hash function.

    A mask generation function takes an octet string of variable length and a
    desired output length as input, and outputs an octet string of the desired
    length. The plaintext-awareness of RSAES-OAEP relies on the random nature of
    the output of the mask generation function, which in turn relies on the
    random nature of the underlying hash.

    :param bytes seed: seed from which mask is generated, an octet string
    :param int length: intended length in octets of the mask, at most 2^32(hLen)
    :param str hasher: hash function (hLen denotes the length in octets of the hash
        function output)

    :return: mask, an octet string of length `length`
    :rtype: bytes

    :raise OverflowError: when `length` is too large for the specified `hasher`
    :raise ValueError: when specified `hasher` is invalid
    """
    if hasher not in HASH_METHODS:
        raise ValueError(f'Invalid hash method: {hasher}')
    
    hash_method = HASH_METHODS[hasher]
    h_len = hash_method().digest_size
    
    if length > (2**32) * h_len:
        raise OverflowError(f'Desired length too long for {hasher}')
    
    t = b''
    counter = 0
    while len(t) < length:
        c = counter.to_bytes(4, byteorder='big')
        t += hash_method(seed + c).digest()
        counter += 1
    
    return t[:length]
__all__ = ['mgf1']
if __name__ == '__main__':
    print('Running doctests 1000x or until failure')
    import doctest

    def test_mgf1():
        """
        >>> mgf1(b'seed', 10)
        b'\x0c\x83\xd3N\xefD\xf0|l\xb7'
        >>> mgf1(b'seed', 20, 'SHA-256')
        b'v\x14\xd3\xa1\xc3\x99\xfe\xac\xfc\x98\xaa\x8c\x1b\x96\x9f\x80\x85\xadt\x0f'
        >>> mgf1(b'', 0)
        b''
        >>> mgf1(b'seed', 2**32 * 20 + 1, 'SHA-1')
        Traceback (most recent call last):
        ...
        OverflowError: Desired length too long for SHA-1
        >>> mgf1(b'seed', 10, 'INVALID')
        Traceback (most recent call last):
        ...
        ValueError: Invalid hash method: INVALID
        """
        pass

    for count in range(1000):
        failures, tests = doctest.testmod()
        if failures:
            break
        if count % 100 == 0 and count:
            print('%i times' % count)
    print('Doctests done')
