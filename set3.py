"""
Crypto Challenges Set 3 (from cryptopals.com)

Author: Clu (notclu@gmail.com)
"""


def cbc_padding_oracle(ciphertext, padding_valid_fn):
    """ Decrypt a CBC encrypted ciphertext using a padding oracle

    :param ciphertext: Ciphertext to decrypt
    :param padding_valid_fn: Function that decrypts the ciphertext, checks the padding, and returns the status of the padding (True or False)
    :return: Recovered plaintext
    """
