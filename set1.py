"""
Crypto Challenges Set 1 (from cryptopals.com)

Author: Clu (notclu@gmail.com)
"""

import string
import M2Crypto
from cc_util import hexstring_to_bytelist, chunks, get_hamming_distance


def hex_to_base64(hexstring):
    """Converts a hex string to a base64 string

    This is the solution to Set 1 Challenge 1.

    ARGS:
        hexstring: The hexstring to base64 encode
    RETURNS:
        The base64 encoded representation of the hexstring

    >>> hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    """
    return hexstring.decode('hex').encode('base64').strip()


def xor_hexstring(string_a, string_b):
    """Preform an XOR between two hexstrings

    This is the solution to Set 1 Challenge 2.

    ARGS:
        string_a: The first hex encoded string
        string_b: The second hex encoded string
    RETURNS:
        The hex encoded XOR of string_a and string_b

    >>> xor_hexstring('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
    '746865206b696420646f6e277420706c6179'
    """
    num_a = int(string_a, 16)
    num_b = int(string_b, 16)
    result_string = hex(num_a ^ num_b)

    # Strip of the 0x and L
    return result_string[2:-1]


def single_byte_xor_break(hexstring):
    """Try to decrypt a hex strings that has been encrypted with a one Byte key

    This is the solution to Set 1 Challenge 3

    ARGS:
        hexstring: The hex encoded, one Byte XOR encrypted data to brute force
    RETURNS:
        A tuple containing the key at position 0 and the decrypted string
        at position 1.

    >>> single_byte_xor_break('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    (88, "Cooking MC's like a pound of bacon")
    """
    hexstring_bytes = hexstring_to_bytelist(hexstring)

    # Try every byte counting the number of letters for each decrypt
    best_guess_num_letters = None
    best_guess = None
    best_guess_key = None

    for i in xrange(0, 255):
        decrypt = [chr(byte ^ i) for byte in hexstring_bytes]
        num_letters = sum(1 for c in decrypt if c.isalpha() or c.isspace())

        # We'll assume the guess that decrypts to the maximum number
        # of letters is the correct guess
        if num_letters > best_guess_num_letters:
            best_guess_num_letters = num_letters
            best_guess = ''.join(decrypt)
            best_guess_key = i

    return best_guess_key, best_guess


def detect_single_char_xor(hexstrings_list):
    """Try to find a single byte xor in a list of hexstrings

    This is the solution to Set 1 Challenge 4

    ARGS:
        hexstrings_list: A list of hexstrings to detect XOR encryption in
    RETURNS:
        The best guess decryption of an XOR encrypted string

    >>> detect_single_char_xor(open('test_data/1_4.txt','r').read().splitlines())
    'Now that the party is jumping'
    """
    best_guess_num_letters = 0
    best_guess = ''

    for hexstring in hexstrings_list:
        decrypted_string = single_byte_xor_break(hexstring)[1]

        # Sometimes NULL characters can terminate valid strings. Ignore them

        letters_in_string = sum(1 for c in decrypted_string
                                if c.isalpha() or c.isspace())

        # Strings with bad characters are typically not a valid ascii string
        if letters_in_string > best_guess_num_letters:
            best_guess_num_letters = letters_in_string
            best_guess = decrypted_string

    return best_guess.strip()


def repeating_key_xor_encrypt(plaintext, key):
    """XOR encrypt a string with a repeating key

    This is the solution to Set 1 Challenge 5

    ARGS:
        plaintext: The plaintext string to XOR encrypt
        key: The key to encrypt with
    RETURNS:
        The hex encoded ciphertext

    >>> repeating_key_xor_encrypt("Burning 'em, if you ain't quick and nimble\\nI go crazy when I hear a cymbal",'ICE')
    '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    """
    pt_bytes = [ord(c) for c in plaintext]
    key_bytes = [ord(c) for c in key]

    ciphertext = []

    # XOR the key, repeating the key as necessary
    for i, byte in enumerate(pt_bytes):
        key = key_bytes[i % len(key_bytes)]
        ciphertext.append(byte ^ key)

    # Return a hex encoded string
    return ''.join('%02x' % byte for byte in ciphertext)


def get_likely_xor_keysizes(ciphertext, number_of_keysizes=1):
    """Return the most likely repeating keysize for a ciphertext encrypted with
       a repeating key XOR.

    This is a helper function for break_repeating_key_xor used further down
    the list of key sizes we need to try.

    ARGS:
        ciphertext: The ciphertext to find likely key sizes for
        number_of_keysizes: An optional variable to set the number of likely
                            key sizes to return
    RETURNS:
        A list of likely key sizes with the most likely key sizes at smaller
        indexes.
    """
    normalized_distances = []
    for keysize in xrange(2, 40):
        key_size_chunks = list(chunks(ciphertext, keysize))
        total_distance = 0

        number_of_blocks = 0
        # If the number of blocks in the average distance calculation is too low
        # we may end up with the wrong keysize. Using 40 blocks seems to give
        # results.
        for i in xrange(0, 40, 2):
            total_distance += get_hamming_distance(key_size_chunks[i], key_size_chunks[i+1])
            number_of_blocks += 1

        avg_distance = float(total_distance)/(number_of_blocks/2)
        normalized_distances.append((keysize, avg_distance/keysize))

    # The most likely keysizes will have the lowest hamming weight
    normalized_distances.sort(key=lambda x: x[1])

    return [i[0] for i in normalized_distances[:number_of_keysizes]]


def break_repeating_key_xor(ciphertext):
    """Try to break a ciphertext encrypted with a repeating key XOR

    This is the solution to Set 1 Challenge 6

    ARGS:
        ciphertext: Attempt to decrypt this ciphertext
    RETURNS:
        The recovered plaintext or None on failure

    >>> break_repeating_key_xor(open('test_data/1_6.txt','r').read().decode('base64'))[:83]
    "I'm back and I'm ringin' the bell \\nA rockin' on the mike while the fly girls yell \\n"
    """

    # Get the 4 most likely keysizes. The first most likely keysize it probably the
    # correct keysize, but if it is not we can try the next couple
    keysizes = get_likely_xor_keysizes(ciphertext, 4)

    for keysize in keysizes:
        ct_chunks = list(chunks(ciphertext, keysize))
        ct_chunks = [[ord(c) for c in chunk] for chunk in ct_chunks]

        # Transpose the blocks so we get lists of the byte at position 0, 1, etc
        transposed_blocks = [[chunk[i] for chunk in ct_chunks if len(chunk) > i]
                             for i in xrange(len(ct_chunks[0]))]

        # Brute force the XOR key one byte at a time
        block_hexstrings = [''.join('%02x' % byte for byte in block)
                            for block in transposed_blocks]

        key = [single_byte_xor_break(hexstring)[0] for hexstring in block_hexstrings]
        key_string = ''.join(chr(c) for c in key)

        plaintext = repeating_key_xor_encrypt(ciphertext, key_string).decode('hex')

        # If everything is a printable ASCII character we definetly have the right
        # key and can stop here
        unprintable_chars = sum(1 for c in plaintext if c not in string.printable)

        if not unprintable_chars:
            return plaintext

    # Unable to find a valid decryption
    return None


def aes_ecb(data, key, op='decrypt'):
    """Encrypt or decrypt a string using AES ECB

    This is the solution to Set 1 Challenge 7

    ARGS:
        data: The data to encrypt or decrypt
        key: The AES key to decrypt with
        op: The operation to perform ('decrypt' or 'encrypt')
    RETURNS:
        The AES-128 ECB decrypted plaintext

    >>> aes_ecb(open('test_data/1_7.txt','r').read().decode('base64'), 'YELLOW SUBMARINE')[:66]
    "I'm back and I'm ringin' the bell \\nA rockin' on the mike while the"
    """
    if op == 'decrypt':
        cipher_op = 0
    elif op == 'encrypt':
        cipher_op = 1
    else:
        raise Exception('Invalid operation')

    ctx = M2Crypto.EVP.Cipher(alg='aes_128_ecb', key=key, iv='\x00', op=cipher_op, padding=0)
    return ctx.update(data) + ctx.final()


def detect_aes_ecb(hexstring_list):
    """Determine if any hexstrings provided have been encrypted with AES 128 ECB

    This is the solution to Set 1 Challenge 8

    ARGS:
        hexstring_list: A list of strings to search for AES 128 ECB encrypted blocks
    RETURNS:
        A list of indices of strings that are likely encrypted with AES 128 ECB

    >>> detect_aes_ecb(open('test_data/1_8.txt','r').read().splitlines())
    [132]
    """
    indexes_that_are_aes_ecb = []

    for i, hexstring in enumerate(hexstring_list):
        blocks = list(chunks(hexstring, 2*16))

        # Count the number of occurrence of each element in the block list
        # if the count list is shorter than the block list that means there
        # are duplicate blocks. EX:
        # ['a','b','c'] -> [1,1,1]
        # ['a','b','a'] -> [2,1]
        block_frequency = {block: blocks.count(block) for block in blocks}
        if len(block_frequency.values()) != len(blocks):
            indexes_that_are_aes_ecb.append(i)

    return indexes_that_are_aes_ecb

if __name__ == '__main__':
    # Run all of the test vectors in the docstrings pulled from http://cryptopals.com
    import doctest
    doctest.testmod(verbose=True)
