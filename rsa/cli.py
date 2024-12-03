"""Commandline scripts.

These scripts are called by the executables defined in setup.py.
"""
import abc
import sys
import typing
import optparse
import rsa
import rsa.key
import rsa.pkcs1
HASH_METHODS = sorted(rsa.pkcs1.HASH_METHODS.keys())
Indexable = typing.Union[typing.Tuple, typing.List[str]]

def keygen() -> None:
    """Key generator."""
    parser = optparse.OptionParser(usage='usage: %prog [options]',
                                   description='Generates a new RSA key pair of "bits" bits.')
    parser.add_option('--pubout', type='string',
                      help='Output filename for the public key. The public key is '
                           'not saved if this option is not present. You can use '
                           'this option to override the default filename of '
                           '<private>_pub.pem when --out is specified.')
    parser.add_option('--out', type='string',
                      help='Output filename for the private key. The key is '
                           'written to stdout if this option is not present.')
    parser.add_option('--form', choices=('PEM', 'DER'), default='PEM',
                      help='key format of the private and public keys - '
                           'default PEM')
    parser.add_option('--nbits', type='int', default=2048,
                      help='Number of bits in the key, default 2048')
    
    (cli, cli_args) = parser.parse_args(sys.argv[1:])
    
    if cli_args:
        parser.print_help()
        raise SystemExit(1)
    
    print('Generating %i-bit key' % cli.nbits, file=sys.stderr)
    (pub_key, priv_key) = rsa.newkeys(cli.nbits)
    
    # Save private key
    if cli.out:
        data = priv_key.save_pkcs1(format=cli.form)
        with open(cli.out, 'wb') as outfile:
            outfile.write(data)
        print('Private key saved to %s' % cli.out, file=sys.stderr)
    else:
        data = priv_key.save_pkcs1(format=cli.form)
        print(data.decode('ascii'))
    
    # Save public key
    if cli.pubout:
        data = pub_key.save_pkcs1(format=cli.form)
        with open(cli.pubout, 'wb') as outfile:
            outfile.write(data)
        print('Public key saved to %s' % cli.pubout, file=sys.stderr)
    elif cli.out:
        data = pub_key.save_pkcs1(format=cli.form)
        public_fn = '%s_pub.pem' % os.path.splitext(cli.out)[0]
        with open(public_fn, 'wb') as outfile:
            outfile.write(data)
        print('Public key saved to %s' % public_fn, file=sys.stderr)

class CryptoOperation(metaclass=abc.ABCMeta):
    """CLI callable that operates with input, output, and a key."""
    keyname = 'public'
    usage = 'usage: %%prog [options] %(keyname)s_key'
    description = ''
    operation = 'decrypt'
    operation_past = 'decrypted'
    operation_progressive = 'decrypting'
    input_help = 'Name of the file to %(operation)s. Reads from stdin if not specified.'
    output_help = 'Name of the file to write the %(operation_past)s file to. Written to stdout if this option is not present.'
    expected_cli_args = 1
    has_output = True
    key_class = rsa.PublicKey

    def __init__(self) -> None:
        self.usage = self.usage % self.__class__.__dict__
        self.input_help = self.input_help % self.__class__.__dict__
        self.output_help = self.output_help % self.__class__.__dict__

    @abc.abstractmethod
    def perform_operation(self, indata: bytes, key: rsa.key.AbstractKey, cli_args: Indexable) -> typing.Any:
        """Performs the program's operation.

        Implement in a subclass.

        :returns: the data to write to the output.
        """
        raise NotImplementedError("This method should be implemented in a subclass.")

    def __call__(self) -> None:
        """Runs the program."""
        cli, cli_args = self.parse_cli()
        key = self.read_key(cli_args[0], cli.keyform)
        indata = self.read_infile(cli.input)
        print(self.operation_progressive.title(), file=sys.stderr)
        outdata = self.perform_operation(indata, key, cli_args)
        if self.has_output:
            self.write_outfile(outdata, cli.output)

    def parse_cli(self) -> typing.Tuple[optparse.Values, typing.List[str]]:
        """Parse the CLI options

        :returns: (cli_opts, cli_args)
        """
        parser = optparse.OptionParser(usage=self.usage, description=self.description)

        parser.add_option('-i', '--input', dest='input', help=self.input_help)
        parser.add_option('-o', '--output', dest='output', help=self.output_help)

        if self.key_class == rsa.PublicKey:
            parser.add_option('--keyform', dest='keyform', choices=['PEM', 'DER'],
                              default='PEM', help='Key format of the %s key - default PEM' % self.keyname)

        (cli, cli_args) = parser.parse_args()

        if len(cli_args) != self.expected_cli_args:
            parser.print_help()
            raise SystemExit(1)

        return (cli, cli_args)

    def read_key(self, filename: str, keyform: str) -> rsa.key.AbstractKey:
        """Reads a public or private key."""
        with open(filename, 'rb') as keyfile:
            keydata = keyfile.read()
        
        if keyform == 'DER':
            return self.key_class.load_pkcs1(keydata, format='DER')
        else:
            return self.key_class.load_pkcs1(keydata, format='PEM')

    def read_infile(self, inname: str) -> bytes:
        """Read the input file"""
        if inname:
            with open(inname, 'rb') as infile:
                return infile.read()
        else:
            return sys.stdin.buffer.read()

    def write_outfile(self, outdata: bytes, outname: str) -> None:
        """Write the output file"""
        if outname:
            with open(outname, 'wb') as outfile:
                outfile.write(outdata)
        else:
            sys.stdout.buffer.write(outdata)

class EncryptOperation(CryptoOperation):
    """Encrypts a file."""
    keyname = 'public'
    description = 'Encrypts a file. The file must be shorter than the key length in order to be encrypted.'
    operation = 'encrypt'
    operation_past = 'encrypted'
    operation_progressive = 'encrypting'

    def perform_operation(self, indata: bytes, pub_key: rsa.key.AbstractKey, cli_args: Indexable=()) -> bytes:
        """Encrypts files."""
        return rsa.encrypt(indata, pub_key)

class DecryptOperation(CryptoOperation):
    """Decrypts a file."""
    keyname = 'private'
    description = 'Decrypts a file. The original file must be shorter than the key length in order to have been encrypted.'
    operation = 'decrypt'
    operation_past = 'decrypted'
    operation_progressive = 'decrypting'
    key_class = rsa.PrivateKey

    def perform_operation(self, indata: bytes, priv_key: rsa.key.AbstractKey, cli_args: Indexable=()) -> bytes:
        """Decrypts files."""
        return rsa.decrypt(indata, priv_key)

class SignOperation(CryptoOperation):
    """Signs a file."""
    keyname = 'private'
    usage = 'usage: %%prog [options] private_key hash_method'
    description = 'Signs a file, outputs the signature. Choose the hash method from %s' % ', '.join(HASH_METHODS)
    operation = 'sign'
    operation_past = 'signature'
    operation_progressive = 'Signing'
    key_class = rsa.PrivateKey
    expected_cli_args = 2
    output_help = 'Name of the file to write the signature to. Written to stdout if this option is not present.'

    def perform_operation(self, indata: bytes, priv_key: rsa.key.AbstractKey, cli_args: Indexable) -> bytes:
        """Signs files."""
        hash_method = cli_args[1]
        return rsa.sign(indata, priv_key, hash_method)

class VerifyOperation(CryptoOperation):
    """Verify a signature."""
    keyname = 'public'
    usage = 'usage: %%prog [options] public_key signature_file'
    description = 'Verifies a signature, exits with status 0 upon success, prints an error message and exits with status 1 upon error.'
    operation = 'verify'
    operation_past = 'verified'
    operation_progressive = 'Verifying'
    key_class = rsa.PublicKey
    expected_cli_args = 2
    has_output = False

    def perform_operation(self, indata: bytes, pub_key: rsa.key.AbstractKey, cli_args: Indexable) -> None:
        """Verifies files."""
        signature_file = cli_args[1]
        with open(signature_file, 'rb') as sigfile:
            signature = sigfile.read()
        
        try:
            rsa.verify(indata, signature, pub_key)
            print('Verification OK', file=sys.stderr)
        except rsa.VerificationError:
            print('Verification failed', file=sys.stderr)
            raise SystemExit(1)
encrypt = EncryptOperation()
decrypt = DecryptOperation()
sign = SignOperation()
verify = VerifyOperation()
