"""Common functionality shared by several modules."""
import typing

class NotRelativePrimeError(ValueError):

    def __init__(self, a: int, b: int, d: int, msg: str='') -> None:
        super().__init__(msg or '%d and %d are not relatively prime, divider=%i' % (a, b, d))
        self.a = a
        self.b = b
        self.d = d

def bit_size(num: int) -> int:
    """
    Number of bits needed to represent a integer excluding any prefix
    0 bits.

    Usage::

        >>> bit_size(1023)
        10
        >>> bit_size(1024)
        11
        >>> bit_size(1025)
        11

    :param num:
        Integer value. If num is 0, returns 0. Only the absolute value of the
        number is considered. Therefore, signed integers will be abs(num)
        before the number's bit length is determined.
    :returns:
        Returns the number of bits in the integer.
    """
    if num == 0:
        return 0
    return len(bin(abs(num))) - 2  # Subtract 2 to remove '0b' prefix

def byte_size(number: int) -> int:
    """
    Returns the number of bytes required to hold a specific long number.

    The number of bytes is rounded up.

    Usage::

        >>> byte_size(1 << 1023)
        128
        >>> byte_size((1 << 1024) - 1)
        128
        >>> byte_size(1 << 1024)
        129

    :param number:
        An unsigned integer
    :returns:
        The number of bytes required to hold a specific long number.
    """
    return (bit_size(number) + 7) // 8

def ceil_div(num: int, div: int) -> int:
    """
    Returns the ceiling function of a division between `num` and `div`.

    Usage::

        >>> ceil_div(100, 7)
        15
        >>> ceil_div(100, 10)
        10
        >>> ceil_div(1, 4)
        1

    :param num: Division's numerator, a number
    :param div: Division's divisor, a number

    :return: Rounded up result of the division between the parameters.
    """
    return -(-num // div)

def extended_gcd(a: int, b: int) -> typing.Tuple[int, int, int]:
    """Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb"""
    x, y = 0, 1
    lastx, lasty = 1, 0

    while b:
        a, (q, b) = b, divmod(a, b)
        x, lastx = lastx - q * x, x
        y, lasty = lasty - q * y, y

    return (a, lastx, lasty)

def inverse(x: int, n: int) -> int:
    """Returns the inverse of x % n under multiplication, a.k.a x^-1 (mod n)

    >>> inverse(7, 4)
    3
    >>> (inverse(143, 4) * 143) % 4
    1
    """
    gcd, a, _ = extended_gcd(x, n)
    if gcd != 1:
        raise NotRelativePrimeError(x, n, gcd)
    return a % n

def crt(a_values: typing.Iterable[int], modulo_values: typing.Iterable[int]) -> int:
    """Chinese Remainder Theorem.

    Calculates x such that x = a[i] (mod m[i]) for each i.

    :param a_values: the a-values of the above equation
    :param modulo_values: the m-values of the above equation
    :returns: x such that x = a[i] (mod m[i]) for each i


    >>> crt([2, 3], [3, 5])
    8

    >>> crt([2, 3, 2], [3, 5, 7])
    23

    >>> crt([2, 3, 0], [7, 11, 15])
    135
    """
    total = 0
    prod = 1

    for m in modulo_values:
        prod *= m

    for a_i, m_i in zip(a_values, modulo_values):
        p = prod // m_i
        total += a_i * inverse(p, m_i) * p

    return total % prod
if __name__ == '__main__':
    import doctest
    doctest.testmod()
