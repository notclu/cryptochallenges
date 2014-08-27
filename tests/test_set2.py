import set2
import cc_util
import os
from functools import partial


def test_pkcs7_pad():
    """ Set 2, Challenge 9 """
    assert set2.pkcs7_pad('YELLOW SUBMARINE', 20) == 'YELLOW SUBMARINE\x04\x04\x04\x04'


def test_aes_cbc_encrypt():
    """ Set 2, Challenge 10 """
    assert (set2.aes_cbc_encrypt('0102030405060708', '1122334455667788', '112233445566778899aabbccddeeff00'.decode('hex'))
            == '\xda\x84\xe4\xf7>{\xbb\x83\xa5\x8d\x04\x05Iv\xaa9')


def test_detect_aes_mode():
    """ Set 2, Challenge 11 """
    ecb_oracle = partial(set2.encryption_oracle, mode=set2.AesMode.ECB)
    cbc_oracle = partial(set2.encryption_oracle, mode=set2.AesMode.CBC)

    assert set2.detect_aes_mode(ecb_oracle) == set2.AesMode.ECB
    assert set2.detect_aes_mode(cbc_oracle) == set2.AesMode.CBC


def test_detect_oracle_block_size():
    assert set2.detect_oracle_block_size(set2.encryption_oracle) == 16


def test_break_ecb_encryption():
    """ Set 2, Challenge 12 """
    unknown_string = ('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                      'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                      'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                      'YnkK').decode('base64')

    oracle = partial(set2.encryption_oracle, key=os.urandom(16), prepend='', append=unknown_string, mode=set2.AesMode.ECB)

    assert set2.break_ecb_encryption(oracle) == unknown_string


def generate_encrypted_profile(email, enc_oracle):
    encoded_profile = cc_util.profile_for(email)

    return enc_oracle(encoded_profile)


def decrypt_and_decode_profile(ciphertext, decryption_oracle):
    decrypted_profile = decryption_oracle(ciphertext)

    return cc_util.key_value_parser(decrypted_profile)


def test_break_encrypted():
    """ Set 2, Challenge 13 """
    key = os.urandom(16)

    enc_oracle = partial(set2.encryption_oracle, key=key, mode=set2.AesMode.ECB, prepend='', append='')
    dec_oracle = partial(set2.decrypt_oracle, key=key, mode=set2.AesMode.ECB)

    gen_profile = partial(generate_encrypted_profile, enc_oracle=enc_oracle)
    dec_profile = partial(decrypt_and_decode_profile, decryption_oracle=dec_oracle)

    # Make sure our test setup is working
    assert dec_profile(gen_profile('me@somewhere.com')) == {'email': 'me@somewhere.com', 'uid': '10', 'role': 'user'}

    # Run the real test
    assert dec_profile(set2.break_encrypted_profile(gen_profile)) == {'email': 'a_longer_email@mydomain.com', 'uid': '10', 'role': 'admin'}

