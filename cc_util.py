"""
Crypto Challenges Util Functions

Author: Clu (notclu@gmail.com)
"""


def chunks(data, chunk_size, adv=None):
    """ Yield successive chunk_size'd chunks from data.
    :param data: Data to split into chunks
    :param chunk_size: Number of elements per chunk
    :param adv: Number of elements between chunks
    :return: A generate that will yield chunk_size'd chunks from data
    """
    adv = chunk_size if not adv else adv

    for i in xrange(0, len(data), adv):
        yield data[i:i+chunk_size]


def hexstring_to_bytelist(hexstring):
    """Split a hexstring, by Byte, into a list of integers
    :param hexstring: Hex encoded string to split
    :return: A list of integers representing the bytes in the hexstring
    """
    return [int(byte, 16) for byte in chunks(hexstring, 2)]


def get_hamming_distance(string_a, string_b):
    """Returns the number of bits that differ between two strings
    :param string_a: First string to compare
    :param string_b: Second string to compare
    :return: The number of bits that differ between string_a and string_b

    """

    a_int = int(string_a.encode('hex'), 16)
    b_int = int(string_b.encode('hex'), 16)

    return bin(a_int ^ b_int).count('1')


def string_xor(a, b):
    """ XOR two strings together on a character by character basis
    :param a: First string to XOR
    :param b: Second string to XOR
    :return: a ^ b
    """
    out = ''
    for a_byte, b_byte in zip(a, b):
        out += chr(ord(a_byte) ^ ord(b_byte))

    return out


def round_down(x, base):
    return x - (x % base)