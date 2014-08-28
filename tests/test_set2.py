import set2
import os
import pytest
from crypto_symmetric import pkcs7_pad, AesMode, AESOracle, remove_pkcs7_padding
from cc_util import profile_for, key_value_parser, chunks
from urllib import quote


def test_pkcs7_pad():
    """ Set 2, Challenge 9 """
    assert pkcs7_pad('YELLOW SUBMARINE', 20) == 'YELLOW SUBMARINE\x04\x04\x04\x04'


def test_aes_cbc_encrypt():
    """ Set 2, Challenge 10 """
    aes_cbc = AESOracle(mode=AesMode.CBC, key='1122334455667788', prepend='', append='')
    iv = '112233445566778899aabbccddeeff00'.decode('hex')

    assert (aes_cbc.encrypt('0102030405060708', iv)
            == ('\xda\x84\xe4\xf7>{\xbb\x83\xa5\x8d\x04\x05Iv\xaa9\xa1X\xdeyu\xa8P\xc4\xcfnoui\xc4\xbb\xfe', iv))


def test_detect_aes_mode():
    """ Set 2, Challenge 11 """
    aes_ecb = AESOracle(mode=AesMode.ECB)
    aes_cbc = AESOracle(mode=AesMode.CBC)

    assert set2.detect_aes_mode(aes_ecb.encrypt) == AesMode.ECB
    assert set2.detect_aes_mode(aes_cbc.encrypt) == AesMode.CBC


def test_detect_oracle_block_size():
    aes_random_mode = AESOracle(mode=AesMode.Random)
    assert set2.detect_oracle_block_size(aes_random_mode.encrypt) == 16


def test_break_ecb_encryption():
    """ Set 2, Challenge 12 """
    unknown_string = ('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                      'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                      'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                      'YnkK').decode('base64')

    aes_ecb = AESOracle(key=os.urandom(16), prepend='', append=unknown_string, mode=AesMode.ECB)

    assert set2.break_ecb_encryption(aes_ecb.encrypt) == unknown_string


def test_break_encrypted():
    """ Set 2, Challenge 13 """
    key = os.urandom(16)

    aes_ecb = AESOracle(key=key, mode=AesMode.ECB, prepend='', append='', encode_fn=profile_for, decode_fn=key_value_parser)

    # Make sure our test setup is working
    assert aes_ecb.decrypt(aes_ecb.encrypt('me@somewhere.com')) == {'email': 'me@somewhere.com', 'uid': '10', 'role': 'user'}

    # Run the real test
    assert aes_ecb.decrypt(set2.break_encrypted_profile(aes_ecb.encrypt)) == {'email': 'a_longer_email@mydomain.com', 'uid': '10', 'role': 'admin'}


def test_break_ecb_prefix_encryption():
    """ Set 2, Challenge 14 """
    unknown_string = ('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                      'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                      'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                      'YnkK').decode('base64')

    aes_ecb = AESOracle(key=os.urandom(16), append=unknown_string, mode=AesMode.ECB)

    assert set2.break_ecb_encryption(aes_ecb.encrypt) == unknown_string


def test_remove_pkcs7_padding():
    """ Set 2, Challenge 15 """
    assert remove_pkcs7_padding('ICE ICE BABY\x04\x04\x04\x04') == 'ICE ICE BABY'

    with pytest.raises(Exception):
        remove_pkcs7_padding('ICE ICE BABY\x05\x05\x05\x05')

    with pytest.raises(Exception):
        remove_pkcs7_padding('ICE ICE BABY\x01\x02\x03\x04')


def test_cbc_bitflipping_attack():
    """ Set 2, Challenge 16 """
    def parse_by_semi(text):
        print text
        print text.split(';')
        return [key_value_parser(s) for s in text.split(';')]

    aes_cbc = AESOracle(key=os.urandom(16), mode=AesMode.CBC,
                        prepend='comment1=cooking%20MCs;userdata=', append=';comment2=%20like%20a%20pound%20of%20bacon',
                        encode_fn=quote, decode_fn=parse_by_semi)

    ciphertext, iv = set2.cbc_bitflipping_attack(aes_cbc.encrypt)

    assert {'admin': 'true'} in aes_cbc.decrypt(ciphertext, iv)