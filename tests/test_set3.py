"""
Crypto Challenges Set 3 Tests

Author: Clu (notclu@gmail.com)
"""

from crypto_symmetric import AESOracle, AesMode, PaddingException
import os
import set3
import struct


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

    padding_check_fn = gen_padding_check(cbc_oracle)

    for test_string in test_strings:
        test_string = test_string.decode('base64')
        ciphertext, iv = cbc_oracle.encrypt(test_string)

        assert set3.cbc_padding_oracle(ciphertext, iv, padding_check_fn) == test_string


def simple_nonce_generator():
    nonce = 0
    i = 0

    while True:
        yield struct.pack('<QQ', nonce, i)
        i += 1


def test_aes_ctr():
    """ Set 3, Challenge 18 """

    test_string = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".decode('base64')

    ctr_oracle = AESOracle(mode=AesMode.CTR, key='YELLOW SUBMARINE', prepend='', append='')

    assert ctr_oracle.decrypt(test_string, simple_nonce_generator()) == "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

    my_test = 'A' * 22

    assert ctr_oracle.decrypt(ctr_oracle.encrypt(my_test, simple_nonce_generator()), simple_nonce_generator()) == my_test