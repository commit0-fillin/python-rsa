"""Core mathematical operations.

This is the actual core RSA implementation, which is only defined
mathematically on integers.
"""

def encrypt_int(message: int, ekey: int, n: int) -> int:
    """Encrypts a message using encryption key 'ekey', working modulo n"""
    return pow(message, ekey, n)

def decrypt_int(cyphertext: int, dkey: int, n: int) -> int:
    """Decrypts a cypher text using the decryption key 'dkey', working modulo n"""
    return pow(cyphertext, dkey, n)
