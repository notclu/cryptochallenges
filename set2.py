"""
Crypto Challenges Set 2 (from cryptopals.com)

Author: Clu (notclu@gmail.com)
"""

import random
import os
import struct
import set1
from cc_util import chunks, string_xor


def pkcs7_pad(message, block_length):
    """ Pad a message to a block length using the PKCS7 padding scheme

    This is the solution to Set 2, Challenge 9

    :param message: Message to pad to block_length
    :param block_length: Block length to pad message to
    :return: The message with PKCS7 padding

    >>> pkcs7_pad('YELLOW SUBMARINE', 20)
    'YELLOW SUBMARINE\\x04\\x04\\x04\\x04'
    """
    number_of_padding_bytes = block_length - (len(message) % block_length)
    padding = struct.pack('B', number_of_padding_bytes) * number_of_padding_bytes

    return message + padding


def aes_cbc_decrypt(ciphertext, key, iv):
    """ Perform AES CBC decryption

    This is the solution to Set 2, Challenge 10

    :param ciphertext: The data to  or decrypt
    :param key: The AES key to use
    :param iv: The initialization vector
    :return: The resulting plaintext

    >>> aes_cbc_decrypt(open('test_data/2_10.txt').read().decode('base64'), 'YELLOW SUBMARINE', '\\x00'*16)[-54:]
    'Come on, Come on, Come on \\nPlay that funky music \\n\\x04\\x04\\x04\\x04'
    """
    xor_block = iv
    plaintext = ''

    for ct_block in chunks(ciphertext, 16):
        plaintext += string_xor(set1.aes_ecb(ct_block, key, op='decrypt'), xor_block)
        xor_block = ct_block

    return plaintext


def aes_cbc_encrypt(plaintext, key, iv):
    """ Perform AES CBC encryption, adding PKCS 7 padding as needed

    :param plaintext: The data to encrypt
    :param key: The AES key to use
    :param iv: The initialization vector
    :return: The resulting ciphertext

    >>> aes_cbc_encrypt('0102030405060708', '1122334455667788', '112233445566778899aabbccddeeff00'.decode('hex') )
    '\\xda\\x84\\xe4\\xf7>{\\xbb\\x83\\xa5\\x8d\\x04\\x05Iv\\xaa9'
    """
    xor_block = iv
    ciphertext = ''

    for pt_block in chunks(plaintext, 16):
        ct_block = set1.aes_ecb(string_xor(pt_block, xor_block), key, op='encrypt')
        ciphertext += ct_block
        xor_block = ct_block

    return ciphertext


def encryption_oracle(plaintext, key=None, prepend=None, append=None):
    """ AES encrypt a plaintext using a random key, random padding, and random selection of CBC or ECB mode

    :param plaintext: Plaintext to encrypt
    :return: Encrypted plaintext
    """
    bytes_to_add = random.randint(5, 10)
    prepend = '\xAA' * bytes_to_add if not prepend else prepend
    append = '\xAA' * bytes_to_add if not append else append

    plaintext = prepend + plaintext + append
    plaintext = pkcs7_pad(plaintext, 16)

    key = os.urandom(16) if not key else key

    if random.randint(0, 1) == 1:
        # cbc
        iv = os.urandom(16)
        ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    else:
        # ecb
        ciphertext = set1.aes_ecb(plaintext, key, op='encrypt')

    return ciphertext


class AesMode(object):
    ECB = 0
    CBC = 1


def detect_aes_mode(encrypt_fn):
    """ Detect if an encryption function is encrypting using ECB mode or CBC mode

    :param encrypt_fn: Encryption function to submit plaintexts to
    :return: AesMode.ECB or AesMode.CBC
    """

    # Encrypt a single byte across multiple blocks. If the function is using ECB there will be repeating
    # cipertext blocks.
    plaintext = 'A' * 1024
    ciphertext = encrypt_fn(plaintext)

    if set1.detect_aes_ecb([ciphertext]):
        return AesMode.ECB
    else:
        return AesMode.CBC

if __name__ == '__main__':
    # Run all of the test vectors in the docstrings pulled from cryptopals.com
    import doctest
    doctest.testmod(verbose=True)