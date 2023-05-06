from .constant_keys import ConstantKeysChecker
from .constant_salts import ConstantSaltsChecker
from .constant_ivs import ConstantIVsChecker
from .pbe_iterations import PBEIterationsChecker
from .rsa_key_sizes import RSAKeySizesChecker
from .unsafe_evp_algorithms import UnsafeEVPAlogirthmsChecker
from .unsafe_algorithms import UnsafeAlgorithmsChecker


class CheckerPrototype:
    def __init__(self, name, desc, criteria):
        self.name = name
        self.desc = desc
        self.criteria = criteria


default_checkers = {
    ConstantKeysChecker: [
        ("crypt", 0),
        ("DES_crypt", 0),
        ("DES_fcrypt", 0),
        ("EVP_CipherInit", 2),
        ("EVP_EncryptInit", 2),
        ("EVP_DecryptInit", 2),
        ("EVP_CipherInit_ex", 3),
        ("EVP_EncryptInit_ex", 3),
        ("EVP_DecryptInit_ex", 3),
        ("EVP_CipherInit_ex2", 2),
        ("EVP_EncryptInit_ex2", 2),
        ("EVP_DecryptInit_ex2", 2),
        ("AES_set_encrypt_key", 0),
        ("AES_set_decrypt_key", 0),
        ("DES_set_key", 0),
    ],
    ConstantSaltsChecker: [
        ("crypt", 1),
        ("DES_crypt", 1),
        ("DES_fcrypt", 1),
        ("EVP_BytesToKey", 2),
    ],
    ConstantIVsChecker: [
        ("EVP_CipherInit", 3),
        ("EVP_EncryptInit", 3),
        ("EVP_DecryptInit", 3),
        ("EVP_CipherInit_ex", 4),
        ("EVP_EncryptInit_ex", 4),
        ("EVP_DecryptInit_ex", 4),
        ("EVP_CipherInit_ex2", 3),
        ("EVP_EncryptInit_ex2", 3),
        ("EVP_DecryptInit_ex2", 3),
        ("AES_cbc_encrypt", 4),
    ],
    PBEIterationsChecker: [("EVP_BytesToKey", 5)],
    RSAKeySizesChecker: [
        ("EVP_RSA_gen", 0),
        ("RSA_generate_key_ex", 1),
        ("RSA_generate_multi_prime_key", 1),
        ("EVP_RSA_gen_key", 0),
    ],
    UnsafeEVPAlogirthmsChecker: [
        ("EVP_BytesToKey", 0),
        ("EVP_CipherInit", 1),
        ("EVP_EncryptInit", 1),
        ("EVP_DecryptInit", 1),
        ("EVP_CipherInit_ex", 1),
        ("EVP_EncryptInit_ex", 1),
        ("EVP_DecryptInit_ex", 1),
        ("EVP_CipherInit_ex2", 1),
        ("EVP_EncryptInit_ex2", 1),
        ("EVP_DecryptInit_ex2", 1),
        ("EVP_DigestInit", 1),
        ("EVP_DigestInit_ex", 1),
        ("EVP_DigestInit_ex2", 1),
    ],
    UnsafeAlgorithmsChecker: [
        ("AES_ecb_encrypt", 0),
        ("DES_ecb_encrypt", 0),
        ("DES_ecb2_encrypt", 0),
        ("DES_ecb3_encrypt", 0),
        ("SHA1", 0),
        ("SHA1_Init", 0),
        ("MD2", 0),
        ("MD2_Init", 0),
        ("MD4", 0),
        ("MD4_Init", 0),
        ("MD5", 0),
        ("MD5_Init", 0),
        # ("EVP_aes_128_ecb", 0),
        # ("EVP_aes_192_ecb", 0),
        # ("EVP_aes_256_ecb", 0)
    ],
}

target_apis = set()
for _, criteria in default_checkers.items():
    for func_name, _ in criteria:
        target_apis.add(func_name)
