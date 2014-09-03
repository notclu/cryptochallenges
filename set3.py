"""
Crypto Challenges Set 3 (from cryptopals.com)

Author: Clu (notclu@gmail.com)
"""

from cc_util import chunks, string_xor
from crypto_symmetric import remove_pkcs7_padding


def cbc_padding_attack_block(ct1, ct2, padding_valid_fn):
    # In = Cn-1 ^ Pn -> Pn = In ^ Cn-1
    I = ''

    block_size = 16

    for num_padding_bytes in xrange(1, block_size+1):
        pad_xor = ''.join(chr(num_padding_bytes ^ ord(i_byte)) for i_byte in I)

        for i in xrange(256):
            c_p = '\x00' * (block_size-num_padding_bytes) + chr(i) + pad_xor

            if padding_valid_fn(ct2, c_p):
                I = chr(i ^ num_padding_bytes) + I
                break

    pt = string_xor(ct1, I)

    return pt


def cbc_padding_oracle(ciphertext, iv, padding_valid_fn):
    """ Decrypt a CBC encrypted ciphertext using a padding oracle

    :param ciphertext: Ciphertext to decrypt
    :param padding_valid_fn: Function that decrypts the ciphertext, checks the padding, and returns the status of the padding (True or False)
    :return: Recovered plaintext
    """

    block_size = 16

    ct_blocks = list(chunks(iv + ciphertext, block_size))

    pt = ''
    for two_blocks in chunks(ct_blocks[::-1], 2, adv=1):
        try:
            pt = cbc_padding_attack_block(two_blocks[1], two_blocks[0], padding_valid_fn) + pt
        except IndexError:
            break

    return remove_pkcs7_padding(pt)