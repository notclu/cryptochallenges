import set2
import os
from crypto_symmetric import pkcs7_pad, AesMode, AESOracle
from cc_util import profile_for, key_value_parser
from functools import partial


def test_pkcs7_pad():
    """ Set 2, Challenge 9 """
    assert pkcs7_pad('YELLOW SUBMARINE', 20) == 'YELLOW SUBMARINE\x04\x04\x04\x04'


def test_aes_cbc_encrypt():
    """ Set 2, Challenge 10 """
    aes_cbc = AESOracle(mode=AesMode.CBC, key='1122334455667788', prepend='', append='')

    assert (aes_cbc.encrypt('0102030405060708', '112233445566778899aabbccddeeff00'.decode('hex'))[:16]
            == '\xda\x84\xe4\xf7>{\xbb\x83\xa5\x8d\x04\x05Iv\xaa9')


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


def generate_encrypted_profile(email, enc_oracle):
    encoded_profile = profile_for(email)

    return enc_oracle(encoded_profile)


def decrypt_and_decode_profile(ciphertext, decryption_oracle):
    decrypted_profile = decryption_oracle(ciphertext)

    return key_value_parser(decrypted_profile)


def test_break_encrypted():
    """ Set 2, Challenge 13 """
    key = os.urandom(16)

    aes_ecb = AESOracle( key=key, mode=AesMode.ECB, prepend='', append='')

    gen_profile = partial(generate_encrypted_profile, enc_oracle=aes_ecb.encrypt)
    dec_profile = partial(decrypt_and_decode_profile, decryption_oracle=aes_ecb.decrypt)

    # Make sure our test setup is working
    assert dec_profile(gen_profile('me@somewhere.com')) == {'email': 'me@somewhere.com', 'uid': '10', 'role': 'user'}

    # Run the real test
    assert dec_profile(set2.break_encrypted_profile(gen_profile)) == {'email': 'a_longer_email@mydomain.com', 'uid': '10', 'role': 'admin'}

def test_break_ecb_prefix_encryption():
    """ Set 2, Challenge 14 """
    unknown_string = ('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                      'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                      'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                      'YnkK').decode('base64')

    aes_ecb = AESOracle(key=os.urandom(16), append=unknown_string, mode=AesMode.ECB)

    assert set2.break_ecb_encryption(aes_ecb.encrypt) == unknown_string