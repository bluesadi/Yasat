import os
import filetype
from collections import defaultdict
import angr

from ..utils.files import Files
from ..knowledge_plugins import Subject

TARGET_APIS = [
    "EVP_BytesToKey",
    "RAND_bytes",
    "EVP_RSA_gen",
    "RSA_generate_key_ex",
    "RSA_generate_multi_prime_key",
    "RSA_generate_key"
]

def scan(path):
    results = defaultdict(int)
    for dirpath, _, filenames in os.walk(path):
        for filename in filenames:
            path = Files.join(dirpath, filename)
            if os.path.exists(path):
                origin_type = filetype.guess(path)
                if origin_type is not None:
                    if origin_type.extension == "elf":
                        proj = angr.Project(path, load_options={"auto_load_libs": True})
                        subject: Subject = proj.kb.subject
                        for target_api in TARGET_APIS:
                            symbol = subject.resolve_external_function(target_api, "ssl")
                            if symbol is not None:
                                results[target_api] += 1
    print(results)