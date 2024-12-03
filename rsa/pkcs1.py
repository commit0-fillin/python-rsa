"""Functions for PKCS#1 version 1.5 encryption and signing

This module implements certain functionality from PKCS#1 version 1.5. For a
very clear example, read http://www.di-mgt.com.au/rsa_alg.html#pkcs1schemes

At least 8 bytes of random padding is used when encrypting a message. This makes
these methods much more secure than the ones in the ``rsa`` module.

WARNING: this module leaks information when decryption fails. The exceptions
that are raised contain the Python traceback information, which can be used to
deduce where in the process the failure occurred. DO NOT PASS SUCH INFORMATION
to your users.
"""
import hashlib
import os
import sys
import typing
from hmac import compare_digest
from . import common, transform, core, key
if typing.TYPE_CHECKING:
    HashType = hashlib._Hash
else:
    HashType = typing.Any
HASH_ASN1 = {'MD5': b'0 0\x0c\x06\x08*\x86H\x86\xf7\r\x02\x05\x05\x00\x04\x10', 'SHA-1': b'0!0\t\x06\x05+\x0e\x03\x02\x1a\x05\x00\x04\x14', 'SHA-224': b'0-0\r\x06\t`\x86H\x01e\x03\x04\x02\x04\x05\x00\x04\x1c', 'SHA-256': b'010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 ', 'SHA-384': b'0A0\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\x040', 'SHA-512': b'0Q0\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\x04@'}
HASH_METHODS: typing.Dict[str, typing.Callable[[], HashType]] = {'MD5': hashlib.md5, 'SHA-1': hashlib.sha1, 'SHA-224': hashlib.sha224, 'SHA-256': hashlib.sha256, 'SHA-384': hashlib.sha384, 'SHA-512': hashlib.sha512}
'Hash methods supported by this library.'
if sys.version_info >= (3, 6):
    HASH_ASN1.update({'SHA3-256': b'010\r\x06\t`\x86H\x01e\x03\x04\x02\x08\x05\x00\x04 ', 'SHA3-384': b'0A0\r\x06\t`\x86H\x01e\x03\x04\x02\t\x05\x00\x040', 'SHA3-512': b'0Q0\r\x06\t`\x86H\x01e\x03\x04\x02\n\x05\x00\x04@'})
    HASH_METHODS.update({'SHA3-256': hashlib.sha3_256, 'SHA3-384': hashlib.sha3_384, 'SHA3-512': hashlib.sha3_512})

class CryptoError(Exception):
    """Base class for all exceptions in this module."""

class DecryptionError(CryptoError):
    """Raised when decryption fails."""

class VerificationError(CryptoError):
    """Raised when verification fails."""

def _pad_for_encryption(message: bytes, target_length: int) -> bytes:
    """Pads the message for encryption, returning the padded message.

    :return: 00 02 RANDOM_DATA 00 MESSAGE

    >>> block = _pad_for_encryption(b'hello', 16)
    >>> len(block)
    16
    >>> block[0:2]
    b'\\x00\\x02'
    >>> block[-6:]
    b'\\x00hello'

    """
    max_msglength = target_length - 11
    msglength = len(message)
    
    if msglength > max_msglength:
        raise OverflowError('%i bytes needed for message, but there is only'
                            ' space for %i' % (msglength, max_msglength))
    
    padding_length = target_length - msglength - 3
    
    padding = b''
    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)
        new_padding = os.urandom(needed_bytes + 5)
        new_padding = new_padding.replace(b'\x00', b'')
        padding = padding + new_padding[:needed_bytes]
    
    return b''.join([b'\x00\x02',
                     padding,
                     b'\x00',
                     message])

def _pad_for_signing(message: bytes, target_length: int) -> bytes:
    """Pads the message for signing, returning the padded message.

    The padding is always a repetition of FF bytes.

    :return: 00 01 PADDING 00 MESSAGE

    >>> block = _pad_for_signing(b'hello', 16)
    >>> len(block)
    16
    >>> block[0:2]
    b'\\x00\\x01'
    >>> block[-6:]
    b'\\x00hello'
    >>> block[2:-6]
    b'\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff'

    """
    max_msglength = target_length - 11
    msglength = len(message)
    
    if msglength > max_msglength:
        raise OverflowError('%i bytes needed for message, but there is only'
                            ' space for %i' % (msglength, max_msglength))
    
    padding_length = target_length - msglength - 3
    
    return b''.join([b'\x00\x01',
                     padding_length * b'\xff',
                     b'\x00',
                     message])

def encrypt(message: bytes, pub_key: key.PublicKey) -> bytes:
    """Encrypts the given message using PKCS#1 v1.5

    :param message: the message to encrypt. Must be a byte string no longer than
        ``k-11`` bytes, where ``k`` is the number of bytes needed to encode
        the ``n`` component of the public key.
    :param pub_key: the :py:class:`rsa.PublicKey` to encrypt with.
    :raise OverflowError: when the message is too large to fit in the padded
        block.

    >>> from rsa import key, common
    >>> (pub_key, priv_key) = key.newkeys(256)
    >>> message = b'hello'
    >>> crypto = encrypt(message, pub_key)

    The crypto text should be just as long as the public key 'n' component:

    >>> len(crypto) == common.byte_size(pub_key.n)
    True

    """
    keylength = common.byte_size(pub_key.n)
    padded = _pad_for_encryption(message, keylength)
    payload = transform.bytes2int(padded)
    encrypted = core.encrypt_int(payload, pub_key.e, pub_key.n)
    block = transform.int2bytes(encrypted, keylength)
    return block

def decrypt(crypto: bytes, priv_key: key.PrivateKey) -> bytes:
    """Decrypts the given message using PKCS#1 v1.5

    The decryption is considered 'failed' when the resulting cleartext doesn't
    start with the bytes 00 02, or when the 00 byte between the padding and
    the message cannot be found.

    :param crypto: the crypto text as returned by :py:func:`rsa.encrypt`
    :param priv_key: the :py:class:`rsa.PrivateKey` to decrypt with.
    :raise DecryptionError: when the decryption fails. No details are given as
        to why the code thinks the decryption fails, as this would leak
        information about the private key.


    >>> import rsa
    >>> (pub_key, priv_key) = rsa.newkeys(256)

    It works with strings:

    >>> crypto = encrypt(b'hello', pub_key)
    >>> decrypt(crypto, priv_key)
    b'hello'

    And with binary data:

    >>> crypto = encrypt(b'\\x00\\x00\\x00\\x00\\x01', pub_key)
    >>> decrypt(crypto, priv_key)
    b'\\x00\\x00\\x00\\x00\\x01'

    Altering the encrypted information will *likely* cause a
    :py:class:`rsa.pkcs1.DecryptionError`. If you want to be *sure*, use
    :py:func:`rsa.sign`.


    .. warning::

        Never display the stack trace of a
        :py:class:`rsa.pkcs1.DecryptionError` exception. It shows where in the
        code the exception occurred, and thus leaks information about the key.
        It's only a tiny bit of information, but every bit makes cracking the
        keys easier.

    >>> crypto = encrypt(b'hello', pub_key)
    >>> crypto = crypto[0:5] + b'X' + crypto[6:] # change a byte
    >>> decrypt(crypto, priv_key)
    Traceback (most recent call last):
    ...
    rsa.pkcs1.DecryptionError: Decryption failed

    """
    blocksize = common.byte_size(priv_key.n)
    encrypted = transform.bytes2int(crypto)
    decrypted = priv_key.blinded_decrypt(encrypted)
    cleartext = transform.int2bytes(decrypted, blocksize)

    # If we can't find the cleartext marker, decryption failed.
    if cleartext[0:2] != b'\x00\x02':
        raise DecryptionError('Decryption failed')

    # Find the 00 separator between the padding and the message
    try:
        sep_idx = cleartext.index(b'\x00', 2)
    except ValueError:
        raise DecryptionError('Decryption failed')

    return cleartext[sep_idx+1:]

def sign_hash(hash_value: bytes, priv_key: key.PrivateKey, hash_method: str) -> bytes:
    """Signs a precomputed hash with the private key.

    Hashes the message, then signs the hash with the given key. This is known
    as a "detached signature", because the message itself isn't altered.

    :param hash_value: A precomputed hash to sign (ignores message).
    :param priv_key: the :py:class:`rsa.PrivateKey` to sign with
    :param hash_method: the hash method used on the message. Use 'MD5', 'SHA-1',
        'SHA-224', SHA-256', 'SHA-384' or 'SHA-512'.
    :return: a message signature block.
    :raise OverflowError: if the private key is too small to contain the
        requested hash.

    """
    # Get the ASN1 code for this hash method
    if hash_method not in HASH_ASN1:
        raise ValueError('Invalid hash method: %s' % hash_method)
    asn1code = HASH_ASN1[hash_method]

    # Encrypt the hash with the private key
    cleartext = asn1code + hash_value
    keylength = common.byte_size(priv_key.n)
    padded = _pad_for_signing(cleartext, keylength)

    payload = transform.bytes2int(padded)
    encrypted = priv_key.blinded_encrypt(payload)
    block = transform.int2bytes(encrypted, keylength)

    return block

def sign(message: bytes, priv_key: key.PrivateKey, hash_method: str) -> bytes:
    """Signs the message with the private key.

    Hashes the message, then signs the hash with the given key. This is known
    as a "detached signature", because the message itself isn't altered.

    :param message: the message to sign. Can be an 8-bit string or a file-like
        object. If ``message`` has a ``read()`` method, it is assumed to be a
        file-like object.
    :param priv_key: the :py:class:`rsa.PrivateKey` to sign with
    :param hash_method: the hash method used on the message. Use 'MD5', 'SHA-1',
        'SHA-224', SHA-256', 'SHA-384' or 'SHA-512'.
    :return: a message signature block.
    :raise OverflowError: if the private key is too small to contain the
        requested hash.

    """
    hash_value = compute_hash(message, hash_method)
    return sign_hash(hash_value, priv_key, hash_method)

def verify(message: bytes, signature: bytes, pub_key: key.PublicKey) -> str:
    """Verifies that the signature matches the message.

    The hash method is detected automatically from the signature.

    :param message: the signed message. Can be an 8-bit string or a file-like
        object. If ``message`` has a ``read()`` method, it is assumed to be a
        file-like object.
    :param signature: the signature block, as created with :py:func:`rsa.sign`.
    :param pub_key: the :py:class:`rsa.PublicKey` of the person signing the message.
    :raise VerificationError: when the signature doesn't match the message.
    :returns: the name of the used hash.

    """
    blocksize = common.byte_size(pub_key.n)
    encrypted = transform.bytes2int(signature)
    decrypted = core.decrypt_int(encrypted, pub_key.e, pub_key.n)
    clearsig = transform.int2bytes(decrypted, blocksize)

    # Get the hash method
    method_name = _find_method_hash(clearsig)
    message_hash = compute_hash(message, method_name)

    # Reconstruct the expected padded hash
    cleartext = HASH_ASN1[method_name] + message_hash
    expected = _pad_for_signing(cleartext, blocksize)

    # Compare with the signed one
    if expected != clearsig:
        raise VerificationError('Verification failed')

    return method_name

def find_signature_hash(signature: bytes, pub_key: key.PublicKey) -> str:
    """Returns the hash name detected from the signature.

    If you also want to verify the message, use :py:func:`rsa.verify()` instead.
    It also returns the name of the used hash.

    :param signature: the signature block, as created with :py:func:`rsa.sign`.
    :param pub_key: the :py:class:`rsa.PublicKey` of the person signing the message.
    :returns: the name of the used hash.
    """
    blocksize = common.byte_size(pub_key.n)
    encrypted = transform.bytes2int(signature)
    decrypted = core.decrypt_int(encrypted, pub_key.e, pub_key.n)
    clearsig = transform.int2bytes(decrypted, blocksize)

    return _find_method_hash(clearsig)

def yield_fixedblocks(infile: typing.BinaryIO, blocksize: int) -> typing.Iterator[bytes]:
    """Generator, yields each block of ``blocksize`` bytes in the input file.

    :param infile: file to read and separate in blocks.
    :param blocksize: block size in bytes.
    :returns: a generator that yields the contents of each block
    """
    while True:
        block = infile.read(blocksize)
        if not block:
            break
        yield block

def compute_hash(message: typing.Union[bytes, typing.BinaryIO], method_name: str) -> bytes:
    """Returns the message digest.

    :param message: the signed message. Can be an 8-bit string or a file-like
        object. If ``message`` has a ``read()`` method, it is assumed to be a
        file-like object.
    :param method_name: the hash method, must be a key of
        :py:const:`rsa.pkcs1.HASH_METHODS`.

    """
    if method_name not in HASH_METHODS:
        raise ValueError('Invalid hash method: %s' % method_name)

    method = HASH_METHODS[method_name]
    hasher = method()

    if isinstance(message, bytes):
        hasher.update(message)
    else:
        for block in yield_fixedblocks(message, 1024):
            hasher.update(block)

    return hasher.digest()

def _find_method_hash(clearsig: bytes) -> str:
    """Finds the hash method.

    :param clearsig: full padded ASN1 and hash.
    :return: the used hash method.
    :raise VerificationFailed: when the hash method cannot be found
    """
    for (hashname, asn1code) in HASH_ASN1.items():
        if clearsig.startswith(asn1code):
            return hashname

    raise VerificationError('Verification failed')
__all__ = ['encrypt', 'decrypt', 'sign', 'verify', 'DecryptionError', 'VerificationError', 'CryptoError']
if __name__ == '__main__':
    print('Running doctests 1000x or until failure')
    import doctest
    for count in range(1000):
        failures, tests = doctest.testmod()
        if failures:
            break
        if count % 100 == 0 and count:
            print('%i times' % count)
    print('Doctests done')
