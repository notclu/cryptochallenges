"""
Symmetric crypto implementation

Author: Clu (notclu@gmail.com)
"""

import struct
import random
import os
import M2Crypto
from cc_util import chunks, string_xor


class PaddingException(Exception):
    pass


class AESOracle(object):
    """Helper class for generating AES encryption/decryption oracles"""
    def __init__(self, mode, key=None, prepend=None, append=None, encode_fn=None, decode_fn=None):
        self.key = os.urandom(16) if key is None else key

        bytes_to_add = random.randint(5, 10)
        self.prepend = '\xAA' * bytes_to_add if prepend is None else prepend
        self.append = '\xAA' * bytes_to_add if append is None else append

        self.encode_fn = encode_fn
        self.decode_fn = decode_fn

        self.mode = mode

        if mode == AesMode.CBC:
            self.encrypt_fn = aes_cbc_encrypt
            self.decrypt_fn = aes_cbc_decrypt
        elif mode == AesMode.ECB:
            self.encrypt_fn = aes_ecb_encrypt
            self.decrypt_fn = aes_ecb_decrypt
        elif mode == AesMode.CTR:
            self.encrypt_fn = aes_ctr_encrypt
            self.decrypt_fn = aes_ctr_decrypt
        elif mode == AesMode.Random:
            self.encrypt_fn = aes_rand_mode_encrypt
            self.decrypt_fn = None
        else:
            raise Exception('Invalid block mode')

    def encrypt(self, plaintext, *args, **kwargs):
        try:
            plaintext = self.encode_fn(plaintext)
        except TypeError:
            pass

        plaintext = self.prepend + plaintext + self.append

        if self.mode != AesMode.CTR:
            plaintext = pkcs7_pad(plaintext, 16)
            assert (len(plaintext) % 16 == 0)

        return self.encrypt_fn(plaintext, self.key,  *args, **kwargs)

    def decrypt(self, ciphertext, *args, **kwargs):
        plaintext = self.decrypt_fn(ciphertext, self.key, *args, **kwargs)

        if self.mode != AesMode.CTR:
            plaintext = remove_pkcs7_padding(plaintext)

        try:
            plaintext = self.decode_fn(plaintext)
        except TypeError:
            pass

        return plaintext


class AesMode(object):
    """An enumeration for AES block modes"""
    ECB = 0
    CBC = 1
    CTR = 2
    Random = 3


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
    """Remove pkcs7 padding from a message
    :param message: Message to remove padding from
    :return: message with padding removed
    """
    bytes_of_padding = int(message[-1].encode('hex'), 16)

    padding = message[-bytes_of_padding:]

    if padding == struct.pack('B', bytes_of_padding) * bytes_of_padding:
        return message[:len(message)-bytes_of_padding]
    else:
        raise PaddingException('Invalid padding')


def aes_ecb_encrypt(plaintext, key):
    return aes_ecb(plaintext, key, op='encrypt')


def aes_ecb_decrypt(ciphertext, key):
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


def aes_cbc_encrypt(plaintext, key, iv=None):
    """ Perform AES CBC encryption, adding PKCS 7 padding as needed
    :param plaintext: The data to encrypt
    :param key: The AES key to use
    :param iv: The initialization vector
    :return: The resulting ciphertext
    """
    iv = os.urandom(16) if iv is None else iv

    xor_block = iv
    ciphertext = ''

    for pt_block in chunks(plaintext, 16):
        ct_block = aes_ecb_encrypt(string_xor(pt_block, xor_block), key)
        ciphertext += ct_block
        xor_block = ct_block

    return ciphertext, iv


def aes_ctr_decrypt(ciphertext, key, nonce_generator):

    plaintext = ''

    for ct_block in chunks(ciphertext, 16):
        nonce = nonce_generator.next()
        key_steam = aes_ecb_encrypt(nonce, key)

        plaintext += string_xor(ct_block, key_steam)

    return plaintext


def aes_ctr_encrypt(plaintext, key, nonce_generator):

    ciphertext = ''

    for pt_block in chunks(plaintext, 16):
        nonce = nonce_generator.next()
        key_steam = aes_ecb_encrypt(nonce, key)

        ciphertext += string_xor(pt_block, key_steam)

    return ciphertext


def aes_rand_mode_encrypt(plaintext, key):
    if random.randint(0, 1) == 0:
        ciphertext, iv = aes_cbc_encrypt(plaintext, key)
        return ciphertext
    else:
        return aes_ecb_encrypt(plaintext, key)
