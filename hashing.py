#we have leveraged on LLMs to debug to get the right regular expressions and tune the tests.

#packages we use
import hashlib
import base64
import subprocess
from pathlib import Path

#ENCODING BINARY DATA FOR URLs
def url_format(data: bytes) -> str:
    """
    Convert a bytes sequence to its URL-encoded representation by percent-
    encoding each byte.
    Each byte in the input is formatted as a two-digit hexadecimal number,
    prefixed with '%', as commonly used in URL encoding.

    Args:
        data (bytes): The input data to encode.

    Returns:
        str: A string where each byte of `data` is represented as '%XX',
        with XX being the lowercase hexadecimal value of the byte.

    Example:
        >>> url_format(b'Hello!')
        '%48%65%6c%6c%6f%21'
    """
    ans = ''.join(f'%{byte:02x}' for byte in data)
    return ans


#USING HASH FUNCTIONS
def compute_hash(algorithm='md5', message=None, output_format='bytes'):
    """
    Parameters
    ----------
    algorithm : str
        Must be one of the following algorithms:
        1. 'md5'
        2. 'sha256'
        3. 'sha512'
        Otherwise throws an error.
    message : bytes (or bytes-like object)
        Encoded message to be hashed with the given algorithm.
    output_format : str
        Must be one of the following:
        i. 'bytes'
        ii. 'hex'
        iii. 'base64'
        Otherwise throws an error

    Returns
    -------
    The hash digest of message, using the given algorithm, in the given
    format. If 'bytes', will return a bytes object. If 'hex' or 'base64' will
    return a string of the given encoding.
    """
    error = ""

    # Validate algorithm parameter
    valid_algorithms = ['md5', 'sha256', 'sha512']
    if algorithm not in valid_algorithms:
        error += "Algorithm must be md5, sha256 or sha512. "

    # Validate output_format parameter
    valid_formats = ['bytes', 'hex', 'base64']
    if output_format not in valid_formats:
        error += "Format must be bytes, hex or base64. "

    # Validate message parameter
    if message is None:
        error += "Message cannot be empty. "

    # Convert message to bytes if it's not already
    if message is not None and not isinstance(message, (bytes, bytearray)):
        error += f"Message must be bytes or bytes-like object. Received {message} "

    if error != "":
        return error
    else:
        # Create hash object
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(message)

        # Return in requested format
        if output_format == 'bytes':
            return hash_obj.digest()
        elif output_format == 'hex':
            return hash_obj.hexdigest()
        elif output_format == 'base64':
            return base64.b64encode(hash_obj.digest()).decode('ascii')


# IMPLEMENTING CORRECT PADDING
def compute_padding(algorithm='md5', output_format='bytes', message=None):
    """
    Parameters
    ----------
    algorithm : str
        One of: 'md5', 'sha256', 'sha512'
    output_format : str
        One of: 'bytes', 'hex', 'base64'
    message : bytes
        Data to hash. Required.

    Returns
    -------
    bytes or str
        The padding that the given algorithm adds to the message before
        processing. To be used in implementation of the length extension attack.
    """
    error = ""

    # Validate algorithm parameter
    valid_algorithms = ['md5', 'sha256', 'sha512']
    if algorithm not in valid_algorithms:
        error += "Algorithm must be md5, sha256 or sha512. "

    # Validate output_format parameter
    valid_formats = ['bytes', 'hex', 'base64']
    if output_format not in valid_formats:
        error += "Format must be bytes, hex or base64. "

    # Validate message parameter
    if message is None:
        error += "Message cannot be empty. "

    # Convert message to bytes if it's not already
    if message is not None and not isinstance(message, (bytes, bytearray)):
        error += f"Message must be bytes or bytes-like object. Received {message} "

    if error != "":
        return error
    else:
        # Get message length in bits
        message_len_bits = len(message) * 8

        # Calculate padding based on algorithm
        if algorithm == 'md5':
            block_size = 64
            length_field_size = 8

            padding_len = (block_size - ((len(message) + 1 + length_field_size) % block_size)) % block_size
            padding = b'\x80' + (b'\x00' * padding_len)
            length_bytes = message_len_bits.to_bytes(8, byteorder='little')
            full_padding = padding + length_bytes

        elif algorithm in ['sha256', 'sha512']:
            if algorithm == 'sha256':
                block_size = 64
                length_field_size = 8
            else:
                block_size = 128
                length_field_size = 16

            padding_len = (block_size - ((len(message) + 1 + length_field_size) % block_size)) % block_size
            padding = b'\x80' + (b'\x00' * padding_len)

            if algorithm == 'sha256':
                length_bytes = message_len_bits.to_bytes(8, byteorder='big')
            else:
                # sha512: high 64 bits zero, low 64 bits hold the length
                length_bytes = (0).to_bytes(8, byteorder='big') + message_len_bits.to_bytes(8, byteorder='big')

            full_padding = padding + length_bytes

        # Return in requested format
        if output_format == 'bytes':
            return full_padding
        elif output_format == 'hex':
            return full_padding.hex()
        elif output_format == 'base64':
            return base64.b64encode(full_padding).decode('ascii')


# Integrating Our Binary into Python
def length_extend_sha256(digest_hex=None, len_padded=None, extension_hex=None, binary="./length_ext"):
    """
    Run the `length_ext` C program and return the forged digest.

    Parameters
    ----------
    digest_hex : str
        64-character hex SHA-256 of `M || pad(M)`. Required.
    len_padded : int
        Length in **bytes** of `M || pad(M)` (must be a multiple of 64). Required.
    extension_hex : str
        Even-length hex string for the data to append. Required.
    binary : str or Path, optional
        Path to the compiled `length_ext` executable (default: ./length_ext).

    Returns
    -------
    str
        64-character hex digest of `M || pad(M) || extension`, or an error message.
    """
    error = ""

    # check parameters
    if digest_hex is None:
        error += "digest_hex cannot be None. "
    elif not isinstance(digest_hex, str):
        error += f"digest_hex must be a string. Received {type(digest_hex).__name__}. "
    elif len(digest_hex) != 64:
        error += f"digest_hex must be exactly 64 characters. Received {len(digest_hex)} characters. "
    elif not all(c in '0123456789abcdefABCDEF' for c in digest_hex):
        error += "digest_hex must contain only hexadecimal characters. "


    if len_padded is None:
        error += "len_padded cannot be None. "
    elif len_padded % 64 != 0:
        error += f"len_padded must be a multiple of 64. Received {len_padded}. "


    if extension_hex is None:
        error += "extension_hex cannot be None. "
    elif len(extension_hex) % 2 != 0:
        error += f"extension_hex must have even length. Received {len(extension_hex)} characters. "
    elif not all(c in '0123456789abcdefABCDEF' for c in extension_hex):
        error += "extension_hex must contain only hexadecimal characters. "

    if not isinstance(binary, (str, Path)):
        error += f"binary must be a string or Path. Received {type(binary).__name__}. "
    #check if there are errors
    if error != "":
        return error

    else:
        binary_path = str(binary)
        if not Path(binary_path).exists():
            return f"Binary not found: {binary_path}"

        cmd = [binary_path, digest_hex, str(len_padded), extension_hex]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=30
            )
            output = result.stdout.strip().lower()

            if len(output) != 64:
                return f"Binary returned invalid digest length: {len(output)} (expected 64)"
            if any(c not in '0123456789abcdef' for c in output):
                return "Binary returned non-hexadecimal output"

            return output

        except subprocess.TimeoutExpired:
            return "Binary execution timed out"
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else "Unknown error"
            return f"Binary execution failed: {error_msg}"
        except Exception as e:
            return f"Unexpected error running binary: {e}"


#THE BEST DEFENSE IS TO ATACKKKKKKK!!!!
def test_attack(message: bytes, extension: bytes) -> None:
    """
    Test a SHA‑256 length‑extension attack by comparing:
    1. The hash of (message || padding(message) || extension)
    2. The hash obtained via a length‑extension routine.
    Args:
    message (bytes): The original message.
    extension (bytes): The data to append via the length‑extension
    attack.
    Raises:
    AssertionError: If the two hashes don’t match.
    """
    # 1) Compute the hash of (message + padding + extension)
    padding = compute_padding('sha256', 'bytes', message)
    extension_hash = compute_hash('sha256', message + padding + extension, 'hex')
    print(f"Conventionally computed extension hash: {extension_hash}")

    orig_hash = compute_hash('sha256', message, 'hex')
    attack_hash = length_extend_sha256(
    orig_hash,
    len(message + padding), # original message length in bytes
    extension.hex(), # hex‑encoded extension
    './length_ext' # path to your extension binary/script
    )
    print(f"Hash computed with Length Extension: {attack_hash}")
    # 3) Verify they agree
    assert extension_hash == attack_hash, "Length‑extension attack failed: hashes differ"



# TEST
if __name__ == "__main__":
    test_msgs = [b'Hello, World!', b'abc', None, 'Theodore is the best rabbit in the world']

    # Test url_format
    print("Testing url_format:")
    testsURL = [b'Hello!', b'SaveTheodore']
    for tstUrl in testsURL:
        print(f"URL format of {tstUrl}: {url_format(tstUrl)}")

    # Test compute_hash
    print("Testing compute_hash:")
    algos = ['md5', 'sha256', 'sha512', 'sHa17', 'Md17']
    fmts = ['bytes', 'hex', 'base64', 'latex', 'goppa']
    for algo in algos:
        print(f"Testing {algo.upper()}:")
        for fmt in fmts:
            for msg in test_msgs:
                result = compute_hash(algo, msg, fmt)
                print(f"  {fmt}: {result}")

    # Test compute_padding
    print("Testing compute_padding:")
    algos_padding = ['md5', 'sha256', 'sha512', 'sha1', 'blake2b']
    fmts_padding = ['bytes', 'hex', 'base64', 'binary', 'ascii']
    for algo in algos_padding:
        print(f"Testing {algo.upper()}:")
        for fmt in fmts_padding:
            for msg in test_msgs:
                result = compute_padding(algo, fmt, msg)
                if isinstance(result, str) and any(err in result for err in [
                    "Algorithm must be", "Format must be", "Message cannot be", "Message must be"
                ]):
                    print(f"  {fmt} with {msg}: {result}")
                else:
                    print(f"  {fmt} with {msg}: Success (length: {len(result) if isinstance(result, (bytes, str)) else 'N/A'})")

    # Test integrating our binary into Python
    print("Testing binary")
    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    padded_len = 64
    extension = "2661646d696e3d74726565"

    result = length_extend_sha256(digest, padded_len, extension)
    if result.startswith(("Binary", "digest_hex", "len_padded", "extension_hex")):
        print(f"Error: {result}")
    else:
        print(f"Original digest: {digest}")
        print(f"Extension (hex): {extension}")
        print(f"Forged digest:   {result}")

    # test attack
    test_attack(b"secret", b"&admin=true")