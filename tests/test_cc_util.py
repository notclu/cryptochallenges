import cc_util


def test_chunks():
    assert list(cc_util.chunks('aa00bb00cc00', 2, 4)) == ['aa', 'bb', 'cc']


def test_hexstring_to_bytelist():
    assert cc_util.hexstring_to_bytelist('01020304050a0b0c0d10') == [1, 2, 3, 4, 5, 10, 11, 12, 13, 16]


def test_get_hamming_distance():
    assert cc_util.get_hamming_distance('this is a test', 'wokka wokka!!!') == 37


def test_string_xor():
    assert cc_util.string_xor('\x0A\x0B\x0C\x0D', 'abcd') == 'kioi'


def test_key_value_parser():
    assert cc_util.key_value_parser('foo=bar&baz=qux&zap=zazzle') == {'foo':'bar', 'baz':'qux', 'zap':'zazzle'}


def test_profile_for():
    assert cc_util.profile_for('foo@bar.com') == 'email=foo%40bar.com&uid=10&role=user'
    assert cc_util.profile_for('foo@bar.com&role=admin') == 'email=foo%40bar.com%26role%3Dadmin&uid=10&role=user'