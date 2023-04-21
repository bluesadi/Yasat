from .common import run_backward_slicing_on_binary

def test_EVP_BytesToKey_arm():
	assert run_backward_slicing_on_binary('binaries/openssl/EVP_BytesToKey_arm', 'EVP_BytesToKey', 5) == [954, 1050, 120, 1686, 1102, 1835, 719, 61, 1123, 105, 820, 727, 1882, 777, 1408, 1738, 807, 162, 1683, 336, 1672, 555, 669, 301, 187]

def test_EVP_BytesToKey_mips():
	assert run_backward_slicing_on_binary('binaries/openssl/EVP_BytesToKey_mips', 'EVP_BytesToKey', 5) == [954, 1050, 120, 1686, 1102, 1835, 719, 61, 1123, 105, 820, 727, 1882, 777, 1408, 1738, 807, 162, 1683, 336, 1672, 555, 669, 301, 187]

def test_RSA_generate_key_arm():
	assert run_backward_slicing_on_binary('binaries/openssl/RSA_generate_key_arm', 'RSA_generate_key', 0) == [1721, 2746, 36, 1563, 2975, 3087, 1338, 3882, 798, 195, 3654, 15, 678, 4013, 1454, 86, 701, 2117, 4081, 1452, 811, 3033, 668, 3047, 1180]

def test_RSA_generate_key_mips():
	assert run_backward_slicing_on_binary('binaries/openssl/RSA_generate_key_mips', 'RSA_generate_key', 0) == [1721, 2746, 36, 1563, 2975, 3087, 1338, 3882, 798, 195, 3654, 15, 678, 4013, 1454, 86, 701, 2117, 4081, 1452, 811, 3033, 668, 3047, 1180]

