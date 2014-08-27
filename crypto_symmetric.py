"""
Symmetric crypto implementation

Author: Clu (notclu@gmail.com)
"""

import struct
import random
import os
import M2Crypto
from functools import partial
from cc_util import chunks, string_xor


class AESOracle(object):
    def __init__(self, mode, key=None, prepend=None, append=None):
        key = os.urandom(16) if key is None else key

        bytes_to_add = random.randint(5, 10)
        self.prepend = '\xAA' * bytes_to_add if prepend is None else prepend
        self.append = '\xAA' * bytes_to_add if append is None else append

        self.mode = mode

        if mode == AesMode.CBC:
            self.encrypt_fn = partial(aes_cbc_encrypt, key=key)
            self.decrypt_fn = partial(aes_cbc_decrypt, key=key)
        elif mode == AesMode.ECB:
            self.encrypt_fn = partial(aes_ecb_encrypt, key=key)
            self.decrypt_fn = partial(aes_ecb_decrypt, key=key)
        elif mode == AesMode.Random:
            self.encrypt_fn = partial(aes_rand_mode_encrypt, key=key)
            self.decrypt_fn = partial(aes_rand_mode_decrypt, key=key)
        else:
            raise Exception('Invalid block mode')

    def encrypt(self, plaintext, iv=None):
        plaintext = self.prepend + plaintext + self.append
        plaintext = pkcs7_pad(plaintext, 16)

        assert (len(plaintext) % 16 == 0)

        iv = os.urandom(16) if iv is None else iv

        return self.encrypt_fn(plaintext, iv=iv)

    def decrypt(self, ciphertext, iv=None):
        plaintext = self.decrypt_fn(ciphertext, iv=iv)

        return remove_pkcs7_padding(plaintext)


class AesMode(object):
    """An enumeration for AES block modes"""
    ECB = 0
    CBC = 1
    Random = 2


def pkcs7_pad(message, block_length):
    """ Pad a message to a block length using the PKCS7 padding scheme
    :param message: Message to pad to block_length
    :param block_length: Block length to pad message to
    :return: The message with PKCS7 padding
    """
    number_of_padding_bytes = block_length - (len(message) % block_length)
    if number_of_padding_bytes == 0:
        number_of_padding_bytes = block_length

    padding = struct.pack('B', number_of_padding_bytes) * number_of_padding_bytes

    return message + padding


def remove_pkcs7_padding(message):
    bytes_of_padding = int(message[-1].encode('hex'), 16)

    return message[:len(message)-bytes_of_padding]


def aes_ecb_encrypt(plaintext, key, iv=None):
    return aes_ecb(plaintext, key, op='encrypt')


def aes_ecb_decrypt(ciphertext, key, iv=None):
    return aes_ecb(ciphertext, key, op='decrypt')


def aes_ecb(data, key, op):
    """Encrypt or decrypt a string using AES ECB
    :param data: The data to encrypt or decrypt
    :param key: The AES key to decrypt with
    :param op: The operation to perform ('decrypt' or 'encrypt')
    :return: The AES-128 ECB decrypted plaintext
    """
    if op == 'decrypt':
        cipher_op = 0
    elif op == 'encrypt':
        cipher_op = 1
    else:
        raise Exception('Invalid operation')

    ctx = M2Crypto.EVP.Cipher(alg='aes_128_ecb', key=key, iv='\x00', op=cipher_op, padding=0)
    return ctx.update(data) + ctx.final()


def aes_cbc_decrypt(ciphertext, key, iv):
    """ Perform AES CBC decryption

    This is the solution to Set 2, Challenge 10
    :param ciphertext: The data to  or decrypt
    :param key: The AES key to use
    :param iv: The initialization vector
    :return: The resulting plaintext
    """
    xor_block = iv
    plaintext = ''

    for ct_block in chunks(ciphertext, 16):
        plaintext += string_xor(aes_ecb_decrypt(ct_block, key), xor_block)
        xor_block = ct_block

    return plaintext


def aes_cbc_encrypt(plaintext, key, iv):
    """ Perform AES CBC encryption, adding PKCS 7 padding as needed
    :param plaintext: The data to encrypt
    :param key: The AES key to use
    :param iv: The initialization vector
    :return: The resulting ciphertext
    """
    xor_block = iv
    ciphertext = ''

    for pt_block in chunks(plaintext, 16):
        ct_block = aes_ecb_encrypt(string_xor(pt_block, xor_block), key)
        ciphertext += ct_block
        xor_block = ct_block

    return ciphertext


def aes_rand_mode_encrypt(plaintext, key, iv):
    if random.randint(0, 1) == 0:
        return aes_cbc_encrypt(plaintext, key, iv)
    else:
        return aes_ecb_encrypt(plaintext, key, iv)


def aes_rand_mode_decrypt(plaintext, key, iv):
    if random.randint(0, 1) == 0:
        return aes_cbc_decrypt(plaintext, key, iv)
    else:
        return aes_ecb_decrypt(plaintext, key, iv)