"""Numerical functions related to primes.

Implementation based on the book Algorithm Design by Michael T. Goodrich and
Roberto Tamassia, 2002.
"""
import rsa.common
import rsa.randnum
__all__ = ['getprime', 'are_relatively_prime']

def gcd(p: int, q: int) -> int:
    """Returns the greatest common divisor of p and q

    >>> gcd(48, 180)
    12
    """
    while q:
        p, q = q, p % q
    return p

def get_primality_testing_rounds(number: int) -> int:
    """Returns minimum number of rounds for Miller-Rabin primality testing,
    based on number bitsize.

    According to NIST FIPS 186-4, Appendix C, Table C.3, minimum number of
    rounds of M-R testing, using an error probability of 2 ** (-100), for
    different p, q bitsizes are:
      * p, q bitsize: 512; rounds: 7
      * p, q bitsize: 1024; rounds: 4
      * p, q bitsize: 1536; rounds: 3
    See: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    """
    bitsize = rsa.common.bit_size(number)
    if bitsize >= 1536:
        return 3
    elif bitsize >= 1024:
        return 4
    elif bitsize >= 512:
        return 7
    else:
        # For smaller bitsizes, use 10 rounds
        return 10

def miller_rabin_primality_testing(n: int, k: int) -> bool:
    """Calculates whether n is composite (which is always correct) or prime
    (which theoretically is incorrect with error probability 4**-k), by
    applying Miller-Rabin primality testing.

    For reference and implementation example, see:
    https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

    :param n: Integer to be tested for primality.
    :type n: int
    :param k: Number of rounds (witnesses) of Miller-Rabin testing.
    :type k: int
    :return: False if the number is composite, True if it's probably prime.
    :rtype: bool
    """
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = rsa.randnum.randint(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def is_prime(number: int) -> bool:
    """Returns True if the number is prime, and False otherwise.

    >>> is_prime(2)
    True
    >>> is_prime(42)
    False
    >>> is_prime(41)
    True
    """
    if number < 2:
        return False
    if number == 2:
        return True
    if number % 2 == 0:
        return False

    return miller_rabin_primality_testing(number, get_primality_testing_rounds(number))

def getprime(nbits: int) -> int:
    """Returns a prime number that can be stored in 'nbits' bits.

    >>> p = getprime(128)
    >>> is_prime(p-1)
    False
    >>> is_prime(p)
    True
    >>> is_prime(p+1)
    False

    >>> from rsa import common
    >>> common.bit_size(p) == 128
    True
    """
    while True:
        integer = rsa.randnum.read_random_odd_int(nbits)

        # Test for primality
        if is_prime(integer):
            return integer

        # If not prime, generate another random integer

def are_relatively_prime(a: int, b: int) -> bool:
    """Returns True if a and b are relatively prime, and False if they
    are not.

    >>> are_relatively_prime(2, 3)
    True
    >>> are_relatively_prime(2, 4)
    False
    """
    return gcd(a, b) == 1
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
