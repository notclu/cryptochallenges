"""
Crypto Challenges Set 2 (from cryptopals.com)

Author: Clu (notclu@gmail.com)
"""

import set1
from cc_util import round_down
from crypto_symmetric import AesMode, pkcs7_pad


def detect_aes_mode(encrypt_fn):
    """ Detect if an encryption function is encrypting using ECB mode or CBC mode
    :param encrypt_fn: Encryption function to submit plaintexts to
    :return: AesMode.ECB or AesMode.CBC
    """

    # Encrypt a single byte across multiple blocks. If the function is using ECB there will be repeating
    # cipertext blocks.
    plaintext = 'A' * 1024
    ciphertext = encrypt_fn(plaintext)

    if set1.detect_aes_ecb([ciphertext]):
        return AesMode.ECB
    else:
        return AesMode.CBC


def detect_oracle_block_size(oracle):
    """ Return the block size, in Bytes of a encryption oracle
    :param oracle: Encryption oracle to submit plaintexts to. oracle(plaintext)
    :return: The block size of the encryption oracle
    """
    first_len = len(oracle('A'))

    # Keep adding bytes until we get another block. The difference in length between
    # the two encryptions is the block size.
    for i in xrange(2, 32):
        second_len = len(oracle('A' * i))

        if second_len != first_len:
            return abs(first_len - second_len)

    return None


def get_decryption_oracle(oracle, block_size, short_input):
    """Derive a decryption oracle for the last byte in a block
    :param oracle: Encryption oracle to submit plaintexts to
    :param block_size: Block size of the encryption oracle
    :param short_input: A plaintext to encrypt that is one byte smaller than a block boundary
    :return: A dictionary mapping all possible encryptions of (plaintext + X) and the plaintext X
    """
    assert ((len(short_input) + 1) % block_size == 0)

    decrypt_oracle = {}

    for i in xrange(0, 255):
        plaintext = short_input + chr(i)
        current_block_start = len(plaintext) - block_size

        ciphertext = oracle(plaintext)
        ciphertext = ciphertext[current_block_start:current_block_start + block_size]

        decrypt_oracle[ciphertext] = chr(i)

    assert (len(decrypt_oracle) == 255)
    return decrypt_oracle


def brute_force_ecb_padding(plaintext, block_size, oracle):
    """Helper function to brute force the PKCS7 padding for the ECB break
    :param plaintext: The current plaintext guess
    :param block_size: The block size of the oracle
    :param oracle: ECB encryption oracle that encrypts AES-128-ECB(your-string || unknown-string, random-key)
    :return: The correct unknown-string or None on failure to match
    """
    last_block_start = round_down(len(plaintext), block_size)
    expected_ciphertext = oracle('')

    # The plaintext may have padding bytes in it so try padding all slices of the last block
    # When the encryption of the plaintext + padding matches the encryption of an empty string we know the plaintext
    # is correct
    for i in xrange(last_block_start, len(plaintext)):
        plaintext_guess = plaintext[:i]

        # Now pad it manually since the hidden string will be appended
        plaintext_guess_w_padding = pkcs7_pad(plaintext_guess, block_size)

        guess_ciphertext = oracle(plaintext_guess_w_padding)[:len(expected_ciphertext)]

        if guess_ciphertext == expected_ciphertext:
            return plaintext_guess

    return None


def break_ecb_encryption(oracle):
    """Break ECB encryption with a chosen plaintext attack
    :param oracle: ECB encryption oracle that encrypts AES-128-ECB(your-string || unknown-string, random-key)
    :return: The unknown-string encrypted by the ECB encryption oracle
    """
    block_size = detect_oracle_block_size(oracle)
    mode = detect_aes_mode(oracle)

    if mode != AesMode.ECB:
        raise Exception('Oracle mode != ECB')

    total_length = len(oracle(''))

    plaintext = ''

    for i in xrange(total_length):
        input_pad = 'A' * (block_size - (i % block_size) - 1)
        short_input = input_pad + plaintext
        current_block_start = round_down(len(short_input), block_size)

        decrypt_oracle = get_decryption_oracle(oracle, block_size, short_input)

        ciphertext = oracle(input_pad)[current_block_start:current_block_start + block_size]

        try:
            plaintext += decrypt_oracle[ciphertext]
        except KeyError:
            # If we're on the last block we will start running into problems with changing padding. Just brute force
            # the padding bytes.
            if (total_length - i) < block_size:
                plaintext = brute_force_ecb_padding(plaintext, block_size, oracle)
                break
            else:
                raise

    return plaintext


def break_encrypted_profile(profile_oracle):
    """Break an encrypted profile oracle by setting role = admin
    :param profile_oracle: An oracle to generate encrypted profiles (in the form generate by cc_util.profile_for)
    :return: A ciphertext with the variable role=admin
    """
    # Pad with A's to get admin into the start of the second block
    admin_enc = profile_oracle('A' * 10 + 'admin')

    # The email must be 20 Bytes shorter than a block boundary in order to line up role=
    user_enc = profile_oracle('a_longer_email@mydomain.com')

    # Add a full padding block to the end so we can truncate the role=user and still decrypt this properly
    padding_block = profile_oracle('A' * 9)[-16:]

    return user_enc[:48] + admin_enc[16:32] + padding_block

