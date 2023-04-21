from .common import run_backward_slicing_on_binary

def test_EVP_BytesToKey_arm():
	assert run_backward_slicing_on_binary('binaries/openssl/EVP_BytesToKey_arm', 'EVP_BytesToKey', 5, cast_to=int) == [1405, 673, 367, 1670, 1679, 1405, 473, 258, 356, 1506, 1019, 402, 1006, 213, 1143, 972, 1866, 1469, 1953, 112, 340, 1036, 1096, 569, 436]

def test_EVP_BytesToKey_mips():
	assert run_backward_slicing_on_binary('binaries/openssl/EVP_BytesToKey_mips', 'EVP_BytesToKey', 5, cast_to=int) == [1405, 673, 367, 1670, 1679, 1405, 473, 258, 356, 1506, 1019, 402, 1006, 213, 1143, 972, 1866, 1469, 1953, 112, 340, 1036, 1096, 569, 436]

def test_RSA_generate_key_arm():
	assert run_backward_slicing_on_binary('binaries/openssl/RSA_generate_key_arm', 'RSA_generate_key', 0, cast_to=int) == [697, 1954, 831, 2870, 2610, 1099, 441, 3915, 2633, 1098, 2003, 2893, 1401, 2638, 475, 634, 2684, 1290, 3398, 1905, 3049, 3312, 3217, 2670, 1685]

def test_RSA_generate_key_mips():
	assert run_backward_slicing_on_binary('binaries/openssl/RSA_generate_key_mips', 'RSA_generate_key', 0, cast_to=int) == [697, 1954, 831, 2870, 2610, 1099, 441, 3915, 2633, 1098, 2003, 2893, 1401, 2638, 475, 634, 2684, 1290, 3398, 1905, 3049, 3312, 3217, 2670, 1685]

def test_EVP_aes_128_ecb_arm():
	assert run_backward_slicing_on_binary('binaries/openssl/EVP_aes_128_ecb_arm', 'EVP_BytesToKey', 0, cast_to=str) == ['EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb']

def test_EVP_aes_128_ecb_mips():
	assert run_backward_slicing_on_binary('binaries/openssl/EVP_aes_128_ecb_mips', 'EVP_BytesToKey', 0, cast_to=str) == ['EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb', 'EVP_aes_128_ecb']

