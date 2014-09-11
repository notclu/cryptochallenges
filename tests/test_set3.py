"""
Crypto Challenges Set 3 Tests

Author: Clu (notclu@gmail.com)
"""

from crypto_symmetric import AESOracle, AesMode, PaddingException
import os
import set3
import struct

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__)) + '/'

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


def test_break_ctr():
    """ Set 3, Challenge 19 """
    test_strings = ["SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ=="
                    "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
                    "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
                    "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
                    "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
                    "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
                    "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
                    "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
                    "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
                    "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
                    "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
                    "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
                    "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
                    "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
                    "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
                    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
                    "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
                    "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
                    "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
                    "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
                    "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
                    "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
                    "U2hlIHJvZGUgdG8gaGFycmllcnM/",
                    "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
                    "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
                    "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
                    "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
                    "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
                    "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
                    "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
                    "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
                    "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
                    "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
                    "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
                    "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
                    "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
                    "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
                    "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
                    "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
                    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="]

    ctr_oracle = AESOracle(mode=AesMode.CTR, key='YELLOW SUBMARINE', prepend='', append='')

    def fixed_nonce():
        while True:
            yield struct.pack('<QQ', 5, 1)

    test_strings = [s.decode('base64') for s in test_strings]
    test_ciphertexts = [ctr_oracle.encrypt(pt, fixed_nonce()) for pt in test_strings]

    # There are not enough samples to break this perfectly
    assert set3.break_repeating_nonce_ctr(test_ciphertexts)[0] == 'i have met them\nAt close of day'

def test_break_ctr_file():
    """ Set 3, Challenge 20 """
    with open(SCRIPT_DIR + 'test_data/3_20.txt', 'r') as test_data:
        ciphertexts = [line.decode('base64') for line in test_data]

    assert set3.break_repeating_nonce_ctr(ciphertexts)[-1] == 'And we outta here / Yo, what happened to peace? / Peace'
