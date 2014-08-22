"""
Crypto Challenges Util Functions

Author: Clu (notclu@gmail.com)
"""


def chunks(data, chunk_size, adv=None):
    """ Yield successive chunk_size'd chunks from data.

    Args:
        data: Data to split into chunks
        chunk_size: Number of elements per chunk
        adv: Number of elements between chunks

    Returns:
        A generate that will yield chunk_size'd chunks from data

    >>> list(chunks('aa00bb00cc00', 2, 4))
    ['aa', 'bb', 'cc']
    """
    adv = chunk_size if not adv else adv

    for i in xrange(0, len(data), adv):
        yield data[i:i+chunk_size]


def hexstring_to_bytelist(hexstring):
    """Split a hexstring, by Byte, into a list of integers

    Args:
        hexstring: Hex encoded string to split
    Returns:
        A list of integers representing the bytes in the hexstring

    >>> hexstring_to_bytelist('01020304050a0b0c0d10')
    [1, 2, 3, 4, 5, 10, 11, 12, 13, 16]
    """
    return [int(byte, 16) for byte in chunks(hexstring, 2)]


def get_hamming_distance(string_a, string_b):
    """Returns the number of bits that differ between two strings

    Args:
        string_a: First string to compare
        string_b: Second string to compare
    Returns:
        The number of bits that differ between string_a and string_b

    >>> get_hamming_distance('this is a test', 'wokka wokka!!!')
    37
    """

    a_int = int(string_a.encode('hex'), 16)
    b_int = int(string_b.encode('hex'), 16)

    return bin(a_int ^ b_int).count('1')


def string_xor(a, b):
    """ XOR two strings together on a character by character basis

    :param a: First string to XOR
    :param b: Second string to XOR
    :return: a ^ b

    >>> string_xor('\\x0A\\x0B\\x0C\\x0D', 'abcd')
    'kioi'
    """
    out = ''
    for a_byte, b_byte in zip(a, b):
        out += chr(ord(a_byte) ^ ord(b_byte))

    return out