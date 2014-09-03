"""
Crypto Challenges Set 3 Tests

Author: Clu (notclu@gmail.com)
"""

from crypto_symmetric import AESOracle, AesMode, PaddingException
import os
import random
import set3


def gen_padding_check(oracle):
    def padding_check_fn(ciphertext, iv):
        try:
            oracle.decrypt(ciphertext, iv=iv)
            return True
        except PaddingException:
            return False

    return padding_check_fn


def test_cbc_padding_oracle():
    """ Set 3, Challenge 17 """
    test_strings = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
                    'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
                    'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
                    'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
                    'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
                    'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
                    'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
                    'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
                    'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
                    'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

    cbc_oracle = AESOracle(mode=AesMode.CBC, key=os.urandom(16), prepend='', append='')

    random_string = test_strings[random.randint(0, len(test_strings)-1)].decode('base64')

    ciphertext, iv = cbc_oracle.encrypt(random_string)
    padding_check_fn = gen_padding_check(cbc_oracle)

    assert set3.cbc_padding_oracle(ciphertext, iv, padding_check_fn) == random_string