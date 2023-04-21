from .constant_keys import ConstantKeysChecker
from .constant_salts import ConstantSaltsChecker
from .pbe_iterations import PBEIterationsChecker
from .rsa_key_sizes import RSAKeySizesChecker

class CheckerPrototype:
    
    def __init__(self, name, desc, criteria):
        self.name = name
        self.desc = desc
        self.criteria = criteria
        
default_checkers = {
    ConstantKeysChecker: [
        ("crypt", 0),
        ("EVP_CipherInit", 2),
        ("EVP_EncryptInit", 2),
        ("EVP_DecryptInit", 2),
        ("EVP_CipherInit_ex", 3),
        ("EVP_EncryptInit_ex", 3),
        ("EVP_DecryptInit_ex", 3),
        ("EVP_CipherInit_ex2", 2),
        ("EVP_EncryptInit_ex2", 2),
        ("EVP_DecryptInit_ex2", 2)
    ],
    ConstantSaltsChecker: [
        ("crypt", 1),
        ("EVP_BytesToKey", 2)
    ],
    PBEIterationsChecker: [
        ("EVP_BytesToKey", 5)
    ],
    RSAKeySizesChecker: [
        ("EVP_RSA_gen", 0),
        ("RSA_generate_key_ex", 1),
        ("RSA_generate_multi_prime_key", 1),
        ("EVP_RSA_gen", 0),
    ]
}