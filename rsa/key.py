"""RSA key generation code.

Create new keys with the newkeys() function. It will give you a PublicKey and a
PrivateKey object.

Loading and saving keys requires the pyasn1 module. This module is imported as
late as possible, such that other functionality will remain working in absence
of pyasn1.

.. note::

    Storing public and private keys via the `pickle` module is possible.
    However, it is insecure to load a key from an untrusted source.
    The pickle module is not secure against erroneous or maliciously
    constructed data. Never unpickle data received from an untrusted
    or unauthenticated source.

"""
import threading
import typing
import warnings
import rsa.prime
import rsa.pem
import rsa.common
import rsa.randnum
import rsa.core
DEFAULT_EXPONENT = 65537
T = typing.TypeVar('T', bound='AbstractKey')

class AbstractKey:
    """Abstract superclass for private and public keys."""
    __slots__ = ('n', 'e', 'blindfac', 'blindfac_inverse', 'mutex')

    def __init__(self, n: int, e: int) -> None:
        self.n = n
        self.e = e
        self.blindfac = self.blindfac_inverse = -1
        self.mutex = threading.Lock()

    @classmethod
    def _load_pkcs1_pem(cls: typing.Type[T], keyfile: bytes) -> T:
        """Loads a key in PKCS#1 PEM format, implement in a subclass.

        :param keyfile: contents of a PEM-encoded file that contains
            the public key.
        :type keyfile: bytes

        :return: the loaded key
        :rtype: AbstractKey
        """
        pass

    @classmethod
    def _load_pkcs1_der(cls: typing.Type[T], keyfile: bytes) -> T:
        """Loads a key in PKCS#1 PEM format, implement in a subclass.

        :param keyfile: contents of a DER-encoded file that contains
            the public key.
        :type keyfile: bytes

        :return: the loaded key
        :rtype: AbstractKey
        """
        pass

    def _save_pkcs1_pem(self) -> bytes:
        """Saves the key in PKCS#1 PEM format, implement in a subclass.

        :returns: the PEM-encoded key.
        :rtype: bytes
        """
        pass

    def _save_pkcs1_der(self) -> bytes:
        """Saves the key in PKCS#1 DER format, implement in a subclass.

        :returns: the DER-encoded key.
        :rtype: bytes
        """
        pass

    @classmethod
    def load_pkcs1(cls: typing.Type[T], keyfile: bytes, format: str='PEM') -> T:
        """Loads a key in PKCS#1 DER or PEM format.

        :param keyfile: contents of a DER- or PEM-encoded file that contains
            the key.
        :type keyfile: bytes
        :param format: the format of the file to load; 'PEM' or 'DER'
        :type format: str

        :return: the loaded key
        :rtype: AbstractKey
        """
        methods = {
            'PEM': cls._load_pkcs1_pem,
            'DER': cls._load_pkcs1_der,
        }

        method = cls._assert_format_exists(format, methods)
        return method(keyfile)

    @staticmethod
    def _assert_format_exists(file_format: str, methods: typing.Mapping[str, typing.Callable]) -> typing.Callable:
        """Checks whether the given file format exists in 'methods'."""
        try:
            return methods[file_format]
        except KeyError:
            formats = ', '.join(sorted(methods.keys()))
            raise ValueError(f'Unsupported format: {file_format}. '
                             f'Supported formats: {formats}')

    def save_pkcs1(self, format: str='PEM') -> bytes:
        """Saves the key in PKCS#1 DER or PEM format.

        :param format: the format to save; 'PEM' or 'DER'
        :type format: str
        :returns: the DER- or PEM-encoded key.
        :rtype: bytes
        """
        methods = {
            'PEM': self._save_pkcs1_pem,
            'DER': self._save_pkcs1_der,
        }

        method = self._assert_format_exists(format, methods)
        return method()

    def blind(self, message: int) -> typing.Tuple[int, int]:
        """Performs blinding on the message.

        :param message: the message, as integer, to blind.
        :param r: the random number to blind with.
        :return: tuple (the blinded message, the inverse of the used blinding factor)

        The blinding is such that message = unblind(decrypt(blind(encrypt(message))).

        See https://en.wikipedia.org/wiki/Blinding_%28cryptography%29
        """
        pass

    def unblind(self, blinded: int, blindfac_inverse: int) -> int:
        """Performs blinding on the message using random number 'blindfac_inverse'.

        :param blinded: the blinded message, as integer, to unblind.
        :param blindfac: the factor to unblind with.
        :return: the original message.

        The blinding is such that message = unblind(decrypt(blind(encrypt(message))).

        See https://en.wikipedia.org/wiki/Blinding_%28cryptography%29
        """
        pass

    def _update_blinding_factor(self) -> typing.Tuple[int, int]:
        """Update blinding factors.

        Computing a blinding factor is expensive, so instead this function
        does this once, then updates the blinding factor as per section 9
        of 'A Timing Attack against RSA with the Chinese Remainder Theorem'
        by Werner Schindler.
        See https://tls.mbed.org/public/WSchindler-RSA_Timing_Attack.pdf

        :return: the new blinding factor and its inverse.
        """
        pass

class PublicKey(AbstractKey):
    """Represents a public RSA key.

    This key is also known as the 'encryption key'. It contains the 'n' and 'e'
    values.

    Supports attributes as well as dictionary-like access. Attribute access is
    faster, though.

    >>> PublicKey(5, 3)
    PublicKey(5, 3)

    >>> key = PublicKey(5, 3)
    >>> key.n
    5
    >>> key['n']
    5
    >>> key.e
    3
    >>> key['e']
    3

    """
    __slots__ = ()

    def __getitem__(self, key: str) -> int:
        return getattr(self, key)

    def __repr__(self) -> str:
        return 'PublicKey(%i, %i)' % (self.n, self.e)

    def __getstate__(self) -> typing.Tuple[int, int]:
        """Returns the key as tuple for pickling."""
        return (self.n, self.e)

    def __setstate__(self, state: typing.Tuple[int, int]) -> None:
        """Sets the key from tuple."""
        self.n, self.e = state
        AbstractKey.__init__(self, self.n, self.e)

    def __eq__(self, other: typing.Any) -> bool:
        if other is None:
            return False
        if not isinstance(other, PublicKey):
            return False
        return self.n == other.n and self.e == other.e

    def __ne__(self, other: typing.Any) -> bool:
        return not self == other

    def __hash__(self) -> int:
        return hash((self.n, self.e))

    @classmethod
    def _load_pkcs1_der(cls, keyfile: bytes) -> 'PublicKey':
        """Loads a key in PKCS#1 DER format.

        :param keyfile: contents of a DER-encoded file that contains the public
            key.
        :return: a PublicKey object

        First let's construct a DER encoded key:

        >>> import base64
        >>> b64der = 'MAwCBQCNGmYtAgMBAAE='
        >>> der = base64.standard_b64decode(b64der)

        This loads the file:

        >>> PublicKey._load_pkcs1_der(der)
        PublicKey(2367317549, 65537)

        """
        from pyasn1.codec.der import decoder
        from pyasn1.type import univ
        
        try:
            asn1_data, remaining = decoder.decode(keyfile)
            if remaining:
                raise ValueError('trailing data')
            n = int(asn1_data[0])
            e = int(asn1_data[1])
        except (ValueError, IndexError):
            raise ValueError('invalid DER data')
        
        return cls(n, e)

    def _save_pkcs1_der(self) -> bytes:
        """Saves the public key in PKCS#1 DER format.

        :returns: the DER-encoded public key.
        :rtype: bytes
        """
        from pyasn1.type import univ
        from pyasn1.codec.der import encoder

        asn1_seq = univ.Sequence()
        asn1_seq.setComponentByPosition(0, univ.Integer(self.n))
        asn1_seq.setComponentByPosition(1, univ.Integer(self.e))

        return encoder.encode(asn1_seq)

    @classmethod
    def _load_pkcs1_pem(cls, keyfile: bytes) -> 'PublicKey':
        """Loads a PKCS#1 PEM-encoded public key file.

        The contents of the file before the "-----BEGIN RSA PUBLIC KEY-----" and
        after the "-----END RSA PUBLIC KEY-----" lines is ignored.

        :param keyfile: contents of a PEM-encoded file that contains the public
            key.
        :return: a PublicKey object
        """
        from rsa import pem
        der = pem.load_pem(keyfile, b'RSA PUBLIC KEY')
        return cls._load_pkcs1_der(der)

    def _save_pkcs1_pem(self) -> bytes:
        """Saves a PKCS#1 PEM-encoded public key file.

        :return: contents of a PEM-encoded file that contains the public key.
        :rtype: bytes
        """
        der = self._save_pkcs1_der()
        return rsa.pem.save_pem(der, b'RSA PUBLIC KEY')

    @classmethod
    def load_pkcs1_openssl_pem(cls, keyfile: bytes) -> 'PublicKey':
        """Loads a PKCS#1.5 PEM-encoded public key file from OpenSSL.

        These files can be recognised in that they start with BEGIN PUBLIC KEY
        rather than BEGIN RSA PUBLIC KEY.

        The contents of the file before the "-----BEGIN PUBLIC KEY-----" and
        after the "-----END PUBLIC KEY-----" lines is ignored.

        :param keyfile: contents of a PEM-encoded file that contains the public
            key, from OpenSSL.
        :type keyfile: bytes
        :return: a PublicKey object
        """
        pass

    @classmethod
    def load_pkcs1_openssl_der(cls, keyfile: bytes) -> 'PublicKey':
        """Loads a PKCS#1 DER-encoded public key file from OpenSSL.

        :param keyfile: contents of a DER-encoded file that contains the public
            key, from OpenSSL.
        :return: a PublicKey object
        """
        pass

class PrivateKey(AbstractKey):
    """Represents a private RSA key.

    This key is also known as the 'decryption key'. It contains the 'n', 'e',
    'd', 'p', 'q' and other values.

    Supports attributes as well as dictionary-like access. Attribute access is
    faster, though.

    >>> PrivateKey(3247, 65537, 833, 191, 17)
    PrivateKey(3247, 65537, 833, 191, 17)

    exp1, exp2 and coef will be calculated:

    >>> pk = PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)
    >>> pk.exp1
    55063
    >>> pk.exp2
    10095
    >>> pk.coef
    50797

    """
    __slots__ = ('d', 'p', 'q', 'exp1', 'exp2', 'coef')

    def __init__(self, n: int, e: int, d: int, p: int, q: int) -> None:
        AbstractKey.__init__(self, n, e)
        self.d = d
        self.p = p
        self.q = q
        self.exp1 = int(d % (p - 1))
        self.exp2 = int(d % (q - 1))
        self.coef = rsa.common.inverse(q, p)

    def __getitem__(self, key: str) -> int:
        return getattr(self, key)

    def __repr__(self) -> str:
        return 'PrivateKey(%i, %i, %i, %i, %i)' % (self.n, self.e, self.d, self.p, self.q)

    def __getstate__(self) -> typing.Tuple[int, int, int, int, int, int, int, int]:
        """Returns the key as tuple for pickling."""
        return (self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef)

    def __setstate__(self, state: typing.Tuple[int, int, int, int, int, int, int, int]) -> None:
        """Sets the key from tuple."""
        self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef = state
        AbstractKey.__init__(self, self.n, self.e)

    def __eq__(self, other: typing.Any) -> bool:
        if other is None:
            return False
        if not isinstance(other, PrivateKey):
            return False
        return self.n == other.n and self.e == other.e and (self.d == other.d) and (self.p == other.p) and (self.q == other.q) and (self.exp1 == other.exp1) and (self.exp2 == other.exp2) and (self.coef == other.coef)

    def __ne__(self, other: typing.Any) -> bool:
        return not self == other

    def __hash__(self) -> int:
        return hash((self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef))

    def blinded_decrypt(self, encrypted: int) -> int:
        """Decrypts the message using blinding to prevent side-channel attacks.

        :param encrypted: the encrypted message
        :type encrypted: int

        :returns: the decrypted message
        :rtype: int
        """
        pass

    def blinded_encrypt(self, message: int) -> int:
        """Encrypts the message using blinding to prevent side-channel attacks.

        :param message: the message to encrypt
        :type message: int

        :returns: the encrypted message
        :rtype: int
        """
        pass

    @classmethod
    def _load_pkcs1_der(cls, keyfile: bytes) -> 'PrivateKey':
        """Loads a key in PKCS#1 DER format.

        :param keyfile: contents of a DER-encoded file that contains the private
            key.
        :type keyfile: bytes
        :return: a PrivateKey object

        First let's construct a DER encoded key:

        >>> import base64
        >>> b64der = 'MC4CAQACBQDeKYlRAgMBAAECBQDHn4npAgMA/icCAwDfxwIDANcXAgInbwIDAMZt'
        >>> der = base64.standard_b64decode(b64der)

        This loads the file:

        >>> PrivateKey._load_pkcs1_der(der)
        PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)

        """
        pass

    def _save_pkcs1_der(self) -> bytes:
        """Saves the private key in PKCS#1 DER format.

        :returns: the DER-encoded private key.
        :rtype: bytes
        """
        pass

    @classmethod
    def _load_pkcs1_pem(cls, keyfile: bytes) -> 'PrivateKey':
        """Loads a PKCS#1 PEM-encoded private key file.

        The contents of the file before the "-----BEGIN RSA PRIVATE KEY-----" and
        after the "-----END RSA PRIVATE KEY-----" lines is ignored.

        :param keyfile: contents of a PEM-encoded file that contains the private
            key.
        :type keyfile: bytes
        :return: a PrivateKey object
        """
        pass

    def _save_pkcs1_pem(self) -> bytes:
        """Saves a PKCS#1 PEM-encoded private key file.

        :return: contents of a PEM-encoded file that contains the private key.
        :rtype: bytes
        """
        pass

def find_p_q(nbits: int, getprime_func: typing.Callable[[int], int]=rsa.prime.getprime, accurate: bool=True) -> typing.Tuple[int, int]:
    """Returns a tuple of two different primes of nbits bits each.

    The resulting p * q has exactly 2 * nbits bits, and the returned p and q
    will not be equal.

    :param nbits: the number of bits in each of p and q.
    :param getprime_func: the getprime function, defaults to
        :py:func:`rsa.prime.getprime`.

        *Introduced in Python-RSA 3.1*

    :param accurate: whether to enable accurate mode or not.
    :returns: (p, q), where p > q

    >>> (p, q) = find_p_q(128)
    >>> from rsa import common
    >>> common.bit_size(p * q)
    256

    When not in accurate mode, the number of bits can be slightly less

    >>> (p, q) = find_p_q(128, accurate=False)
    >>> from rsa import common
    >>> common.bit_size(p * q) <= 256
    True
    >>> common.bit_size(p * q) > 240
    True

    """
    pass

def calculate_keys_custom_exponent(p: int, q: int, exponent: int) -> typing.Tuple[int, int]:
    """Calculates an encryption and a decryption key given p, q and an exponent,
    and returns them as a tuple (e, d)

    :param p: the first large prime
    :param q: the second large prime
    :param exponent: the exponent for the key; only change this if you know
        what you're doing, as the exponent influences how difficult your
        private key can be cracked. A very common choice for e is 65537.
    :type exponent: int

    """
    pass

def calculate_keys(p: int, q: int) -> typing.Tuple[int, int]:
    """Calculates an encryption and a decryption key given p and q, and
    returns them as a tuple (e, d)

    :param p: the first large prime
    :param q: the second large prime

    :return: tuple (e, d) with the encryption and decryption exponents.
    """
    pass

def gen_keys(nbits: int, getprime_func: typing.Callable[[int], int], accurate: bool=True, exponent: int=DEFAULT_EXPONENT) -> typing.Tuple[int, int, int, int]:
    """Generate RSA keys of nbits bits. Returns (p, q, e, d).

    Note: this can take a long time, depending on the key size.

    :param nbits: the total number of bits in ``p`` and ``q``. Both ``p`` and
        ``q`` will use ``nbits/2`` bits.
    :param getprime_func: either :py:func:`rsa.prime.getprime` or a function
        with similar signature.
    :param exponent: the exponent for the key; only change this if you know
        what you're doing, as the exponent influences how difficult your
        private key can be cracked. A very common choice for e is 65537.
    :type exponent: int
    """
    pass

def newkeys(nbits: int, accurate: bool=True, poolsize: int=1, exponent: int=DEFAULT_EXPONENT) -> typing.Tuple[PublicKey, PrivateKey]:
    """Generates public and private keys, and returns them as (pub, priv).

    The public key is also known as the 'encryption key', and is a
    :py:class:`rsa.PublicKey` object. The private key is also known as the
    'decryption key' and is a :py:class:`rsa.PrivateKey` object.

    :param nbits: the number of bits required to store ``n = p*q``.
    :param accurate: when True, ``n`` will have exactly the number of bits you
        asked for. However, this makes key generation much slower. When False,
        `n`` may have slightly less bits.
    :param poolsize: the number of processes to use to generate the prime
        numbers. If set to a number > 1, a parallel algorithm will be used.
        This requires Python 2.6 or newer.
    :param exponent: the exponent for the key; only change this if you know
        what you're doing, as the exponent influences how difficult your
        private key can be cracked. A very common choice for e is 65537.
    :type exponent: int

    :returns: a tuple (:py:class:`rsa.PublicKey`, :py:class:`rsa.PrivateKey`)

    The ``poolsize`` parameter was added in *Python-RSA 3.1* and requires
    Python 2.6 or newer.

    """
    pass
__all__ = ['PublicKey', 'PrivateKey', 'newkeys']
if __name__ == '__main__':
    import doctest
    try:
        for count in range(100):
            failures, tests = doctest.testmod()
            if failures:
                break
            if count % 10 == 0 and count or count == 1:
                print('%i times' % count)
    except KeyboardInterrupt:
        print('Aborted')
    else:
        print('Doctests done')
