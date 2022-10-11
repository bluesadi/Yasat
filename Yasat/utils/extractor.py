from operator import mod
import filetype
import zipfile
import binwalk
import os
import shutil

import logging

l = logging.getLogger(name=__name__)

class Extractor:
    
    def _decompress_zip(self, path, to_path):
        with zipfile.ZipFile(path, 'r') as ref:
            ref.extractall(to_path)
            
    def _extract_from_firmware_bin(self, origin_path, firmware_bin_path):
        binaries = []
        for module in binwalk.scan(firmware_bin_path, '-r', '-y', 'filesystem', signature=True, quiet=True, extract=True):
            for result in module.results:
                if result.file.path in module.extractor.output:
                    if result.offset in module.extractor.output[result.file.path].extracted:
                        extracted_dirs = module.extractor.output[result.file.path].extracted[result.offset].files
                        for extracted_dir in extracted_dirs:
                            for extracted_root, _, extracted_files in os.walk(extracted_dir):
                                for extracted_file in extracted_files:
                                    binary_path = os.path.join(extracted_root, extracted_file)
                                    if not os.path.islink(binary_path):
                                        binary_type = filetype.guess(binary_path)
                                        if binary_type is not None and binary_type.mime == 'application/x-executable':
                                            binaries.append(Binary(origin_path, binary_path))
        return binaries

    def extract(self, origin_path, to_path):
        origin_type = filetype.guess(origin_path)
        if origin_type is not None:
            if origin_type.mime == 'application/x-executable':
                # Case 1: Executable file
                binary_path = shutil.copy(origin_path, to_path)
                return [Binary(origin_path, binary_path)]
            else:
                # Case 2: Firmware (archive)
                binaries = []
                # Find a proper decompressing function
                decompress_func = getattr(self, f'_decompress_{origin_type.extension}')
                if decompress_func is not None:
                    decompress_func(origin_path, to_path)
                    for root, _, files in os.walk(to_path):
                        for filename in files:
                            firmware_bin_path = os.path.join(root, filename)
                            # Try to extract binaries from firmware via binwalk
                            binaries += self._extract_from_firmware_bin(origin_path, firmware_bin_path)
                else:
                    l.warning(f'Failed to decompress {origin_path}')
                return binaries
        else:
            # Case 3: Firmware (binary)
            firmware_bin_path = shutil.copy(origin_path, to_path)
            binaries = self._extract_from_firmware_bin(origin_path, firmware_bin_path)
            if len(binaries) > 0:
                return binaries
            else:
                l.warning(f'Failed to extract from {origin_path}')
                return []

class Binary():
    
    def __init__(self, origin_path, binary_path):
        self.origin_path = origin_path
        self.binary_path = binary_path