"""Functions that load and write PEM-encoded files."""
import base64
import typing
FlexiText = typing.Union[str, bytes]

def _markers(pem_marker: FlexiText) -> typing.Tuple[bytes, bytes]:
    """
    Returns the start and end PEM markers, as bytes.
    """
    if isinstance(pem_marker, str):
        pem_marker = pem_marker.encode('ascii')
    return (b'-----BEGIN ' + pem_marker + b'-----',
            b'-----END ' + pem_marker + b'-----')

def _pem_lines(contents: bytes, pem_start: bytes, pem_end: bytes) -> typing.Iterator[bytes]:
    """Generator over PEM lines between pem_start and pem_end."""
    in_pem_part = False
    for line in contents.split(b'\n'):
        line = line.strip()
        if line == pem_start:
            in_pem_part = True
        elif in_pem_part:
            if line == pem_end:
                break
            yield line

def load_pem(contents: FlexiText, pem_marker: FlexiText) -> bytes:
    """Loads a PEM file.

    :param contents: the contents of the file to interpret
    :param pem_marker: the marker of the PEM content, such as 'RSA PRIVATE KEY'
        when your file has '-----BEGIN RSA PRIVATE KEY-----' and
        '-----END RSA PRIVATE KEY-----' markers.

    :return: the base64-decoded content between the start and end markers.

    @raise ValueError: when the content is invalid, for example when the start
        marker cannot be found.

    """
    if isinstance(contents, str):
        contents = contents.encode('ascii')
    
    (pem_start, pem_end) = _markers(pem_marker)
    pem_lines = [line for line in _pem_lines(contents, pem_start, pem_end)]
    
    if not pem_lines:
        raise ValueError('No PEM start marker "%s" found' % pem_start)
    
    try:
        return base64.b64decode(b''.join(pem_lines))
    except Exception as e:
        raise ValueError('Invalid PEM data') from e

def save_pem(contents: bytes, pem_marker: FlexiText) -> bytes:
    """Saves a PEM file.

    :param contents: the contents to encode in PEM format
    :param pem_marker: the marker of the PEM content, such as 'RSA PRIVATE KEY'
        when your file has '-----BEGIN RSA PRIVATE KEY-----' and
        '-----END RSA PRIVATE KEY-----' markers.

    :return: the base64-encoded content between the start and end markers, as bytes.

    """
    (pem_start, pem_end) = _markers(pem_marker)
    b64 = base64.b64encode(contents).replace(b'\n', b'')
    pem_lines = [pem_start]
    
    for block_start in range(0, len(b64), 64):
        block = b64[block_start:block_start + 64]
        pem_lines.append(block)
    
    pem_lines.append(pem_end)
    return b'\n'.join(pem_lines) + b'\n'
