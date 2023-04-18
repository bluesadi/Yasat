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
        ("crypt", 0)
    ],
    ConstantSaltsChecker: [
        ("crypt", 1)
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