"""
Crypto Challenges Set 3 Tests

Author: Clu (notclu@gmail.com)
"""

from crypto_symmetric import AESOracle, AesMode
import os
import random
import set3


def gen_padding_check(oracle):
    def padding_check_fn(ciphertext):
        try:
            oracle.decrypt(ciphertext)
            return True
        except Exception:
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

    random_string = test_strings[random.randint(0,len(test_strings))].decode('base64')

    ciphertext = cbc_oracle.encrypt(random_string)

    assert set3.cbc_padding_oracle(ciphertext, gen_padding_check(cbc_oracle)) == random_string