"""
Crypto Challenges Set 2 (from cryptopals.com)

Author: Clu (notclu@gmail.com)
"""

import random
import os
import struct
import set1
from cc_util import chunks, string_xor
from functools import partial


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


def encryption_oracle(plaintext, key=None, prepend=None, append=None, mode=None):
    """ AES encrypt a plaintext using a random key, random padding, and random selection of CBC or ECB mode

    :param plaintext: Plaintext to encrypt
    :return: Encrypted plaintext
    """
    bytes_to_add = random.randint(5, 10)
    prepend = '\xAA' * bytes_to_add if prepend is None else prepend
    append = '\xAA' * bytes_to_add if append is None else append

    plaintext = prepend + plaintext + append
    plaintext = pkcs7_pad(plaintext, 16)

    assert(len(plaintext) % 16 == 0)

    key = os.urandom(16) if key is None else key

    mode = random.randint(0, 1) if mode is None else mode

    if mode == AesMode.CBC:
        # cbc
        iv = os.urandom(16)
        ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    elif mode == AesMode.ECB:
        # ecb
        ciphertext = set1.aes_ecb(plaintext, key, op='encrypt')
    else:
        raise Exception('Invalid block mode')

    return ciphertext


class AesMode(object):
    ECB = 0
    CBC = 1


def detect_aes_mode(encrypt_fn):
    """ Detect if an encryption function is encrypting using ECB mode or CBC mode

    This is the solution to set 2 challenge 11

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


def detect_oracle_block_size(oracle):
    """ Return the block size, in Bytes of a encryption oracle

    :param oracle: Encryption oracle to submit plaintexts to. oracle(plaintext)
    >>> detect_oracle_block_size(encryption_oracle)
    16
    """
    first_len = len(oracle('A'))

    # Keep adding bytes until we get another block. The difference in length between
    # the two encryptions is the block size.
    for i in xrange(2, 32):
        second_len = len(oracle('A' * i))

        if second_len != first_len:
            return abs(first_len - second_len)

    return None


def get_decryption_oracle(oracle, block_size, short_input):
    """Derive a decryption oracle for the last byte in a block

    :param oracle: Encryption oracle to submit plaintexts to
    :param block_size: Block size of the encryption oracle
    :param short_input: A plaintext to encrypt that is one byte smaller than a block boundary
    :return: A dictionary mapping all possible encryptions of (plaintext + X) and the plaintext X
    """
    assert((len(short_input) + 1) % block_size == 0)

    decrypt_oracle = {}

    for i in xrange(0, 255):
        plaintext = short_input + chr(i)
        current_block_start = len(plaintext) - block_size

        ciphertext = oracle(plaintext)
        ciphertext = ciphertext[current_block_start:current_block_start+block_size]

        decrypt_oracle[ciphertext] = chr(i)

    assert (len(decrypt_oracle) == 255)
    return decrypt_oracle


def break_ecb_decryption():
    """Break ECB encryption with a chosen plaintext attack

    This is the solution to Set 2 Challenge 12
    """
    unknown_string = ('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                      'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                      'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                      'YnkK').decode('base64')

    fixed_key_oracle = partial(encryption_oracle, key=os.urandom(16), prepend='', append=unknown_string,
                               mode=AesMode.ECB)

    block_size = detect_oracle_block_size(fixed_key_oracle)
    mode = detect_aes_mode(fixed_key_oracle)

    if mode != AesMode.ECB:
        raise Exception('Oracle mode != ECB')

    total_length = len(fixed_key_oracle(''))

    plaintext = ''

    for i in xrange(total_length):
        input_pad = 'A' * (block_size - (i % block_size) - 1)
        short_input = input_pad + plaintext
        current_block_start = len(short_input)+1 - block_size

        decrypt_oracle = get_decryption_oracle(fixed_key_oracle, block_size, short_input)

        ciphertext = fixed_key_oracle(input_pad)[current_block_start:current_block_start+block_size]

        try:
            plaintext += decrypt_oracle[ciphertext]
        except KeyError:
            # If we're on the last block we will start running into problems with changing padding
            if (total_length - i) < block_size:
                for j in xrange(current_block_start, len(plaintext)):
                    plaintext_guess = plaintext[:j]

                    # Now pad it manually since the hidden string will be appended
                    plaintext_guess_w_padding = pkcs7_pad(plaintext_guess, block_size)

                    expected_ciphertext = fixed_key_oracle('')
                    guess_ciphertext = fixed_key_oracle(plaintext_guess_w_padding)[:len(expected_ciphertext)]

                    if guess_ciphertext == expected_ciphertext:
                        return plaintext_guess
            else:
                raise

    return plaintext


if __name__ == '__main__':
    # Run all of the test vectors in the docstrings pulled from cryptopals.com
    import doctest

    doctest.testmod(verbose=True)
