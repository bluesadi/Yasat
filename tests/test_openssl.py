from .common import run_backward_slicing_on_binary

def test_EVP_BytesToKey_arm():
	assert run_backward_slicing_on_binary('binaries/openssl/EVP_BytesToKey_arm', 'EVP_BytesToKey', 5) == [760, 284, 169, 944, 196, 1858, 1748, 96, 946, 435, 1132, 1052, 905, 1517, 1117, 140, 305, 1086, 1213, 287, 296, 615, 695, 1232, 670, 575, 1862, 1286, 434, 1152, 1151, 1229, 1916, 161, 1832, 96, 1769, 1130, 992, 1212, 1886, 886, 1193, 673, 1030, 1393, 555, 1530, 785, 115]

def test_EVP_BytesToKey_mips():
	assert run_backward_slicing_on_binary('binaries/openssl/EVP_BytesToKey_mips', 'EVP_BytesToKey', 5) == [760, 284, 169, 944, 196, 1858, 1748, 96, 946, 435, 1132, 1052, 905, 1517, 1117, 140, 305, 1086, 1213, 287, 296, 615, 695, 1232, 670, 575, 1862, 1286, 434, 1152, 1151, 1229, 1916, 161, 1832, 96, 1769, 1130, 992, 1212, 1886, 886, 1193, 673, 1030, 1393, 555, 1530, 785, 115]

