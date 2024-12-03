"""Functions for parallel computation on multiple cores.

Introduced in Python-RSA 3.1.

.. note::

    Requires Python 2.6 or newer.

"""
import multiprocessing as mp
from multiprocessing.connection import Connection
import rsa.prime
import rsa.randnum

def getprime(nbits: int, poolsize: int) -> int:
    """Returns a prime number that can be stored in 'nbits' bits.

    Works in multiple threads at the same time.

    >>> p = getprime(128, 3)
    >>> rsa.prime.is_prime(p-1)
    False
    >>> rsa.prime.is_prime(p)
    True
    >>> rsa.prime.is_prime(p+1)
    False

    >>> from rsa import common
    >>> common.bit_size(p) == 128
    True

    """
    def worker(nbits: int, pipe: Connection) -> None:
        while True:
            prime = rsa.prime.getprime(nbits)
            pipe.send(prime)

    pipes = []
    processes = []
    for _ in range(poolsize):
        recv_end, send_end = mp.Pipe(False)
        p = mp.Process(target=worker, args=(nbits, send_end))
        pipes.append(recv_end)
        processes.append(p)
        p.start()

    result = pipes[0].recv()
    
    for p in processes:
        p.terminate()

    return result
__all__ = ['getprime']
if __name__ == '__main__':
    print('Running doctests 1000x or until failure')
    import doctest
    for count in range(100):
        failures, tests = doctest.testmod()
        if failures:
            break
        if count % 10 == 0 and count:
            print('%i times' % count)
    print('Doctests done')
