import set1
import os

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__)) + '/'


def test_hex_to_base64():
    """ Set 1, Challenge 1 """
    assert (set1.hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
            == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')


def test_xor_hexstring():
    """ Set 1, Challenge 2 """
    assert (set1.xor_hexstring('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
            == '746865206b696420646f6e277420706c6179')


def test_single_byte_xor_break():
    """ Set 1, Challenge 3 """
    assert (set1.single_byte_xor_break('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
            == (88, "Cooking MC's like a pound of bacon"))


def test_detect_single_char_xor():
    """ Set 1, Challenge 4 """
    assert set1.detect_single_char_xor(open(SCRIPT_DIR + 'test_data/1_4.txt', 'r').read().splitlines()) == 'Now that the party is jumping'


def test_repeating_key_xor_encrypt():
    """ Set 1, Challenge 5 """
    assert (set1.repeating_key_xor_encrypt("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", 'ICE')
            == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')


def test_break_repeating_key_xor():
    """ Set 1, Challenge 6 """
    assert (set1.break_repeating_key_xor(open(SCRIPT_DIR + 'test_data/1_6.txt', 'r').read().decode('base64'))[:83]
            == "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \n")


def test_aes_ecb():
    """ Set 1, Challenge 7 """
    assert (set1.aes_ecb(open(SCRIPT_DIR + 'test_data/1_7.txt', 'r').read().decode('base64'), 'YELLOW SUBMARINE')[:66]
            == "I'm back and I'm ringin' the bell \nA rockin' on the mike while the")


def test_detect_aes_ecb():
    """ Set 1 Challenge 8 """
    assert set1.detect_aes_ecb(open(SCRIPT_DIR + 'test_data/1_8.txt', 'r').read().splitlines()) == [132]
