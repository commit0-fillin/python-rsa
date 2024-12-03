"""Utility functions."""
import sys
from optparse import OptionParser
import rsa.key

def private_to_public() -> None:
    """Reads a private key and outputs the corresponding public key."""
    parser = OptionParser(usage='usage: %prog [options]')
    parser.add_option('--private', dest='private_key_file', help='Private key file in PEM format', metavar='FILE')
    parser.add_option('--public', dest='public_key_file', help='Output file for public key in PEM format', metavar='FILE')
    
    (options, args) = parser.parse_args()
    
    if not options.private_key_file:
        parser.error('Private key file not specified')
    if not options.public_key_file:
        parser.error('Public key output file not specified')
    
    try:
        with open(options.private_key_file, 'rb') as private_file:
            private_key = rsa.key.PrivateKey.load_pkcs1(private_file.read())
    except Exception as e:
        print(f"Error reading private key: {str(e)}")
        sys.exit(1)
    
    public_key = rsa.key.PublicKey(private_key.n, private_key.e)
    
    try:
        with open(options.public_key_file, 'wb') as public_file:
            public_file.write(public_key.save_pkcs1())
        print(f"Public key has been saved to {options.public_key_file}")
    except Exception as e:
        print(f"Error writing public key: {str(e)}")
        sys.exit(1)
