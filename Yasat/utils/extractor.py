import filetype
import zipfile
import os
import shutil
from typing import List
import logging

import binwalk

from ..binary import Binary

l = logging.getLogger(__name__)


class Extractor:
    """
    Basically dirty work.
    You won't want to dive into it.
    """

    def _decompress_zip(self, path, to_path):
        with zipfile.ZipFile(path, "r") as ref:
            ref.extractall(to_path)

    def __extract_from_firmware_bin(self, firmware_bin_path):
        binary_paths = []
        for module in binwalk.scan(
            firmware_bin_path,
            "-r",
            "-y",
            "filesystem",
            signature=True,
            quiet=True,
            extract=True,
        ):
            for result in module.results:
                if result.file.path in module.extractor.output:
                    if (
                        result.offset
                        in module.extractor.output[result.file.path].extracted
                    ):
                        extracted_dirs = (
                            module.extractor.output[result.file.path]
                            .extracted[result.offset]
                            .files
                        )
                        for extracted_dir in extracted_dirs:
                            for extracted_root, _, extracted_files in os.walk(
                                extracted_dir
                            ):
                                for extracted_file in extracted_files:
                                    binary_path = os.path.join(
                                        extracted_root, extracted_file
                                    )
                                    if not os.path.islink(binary_path):
                                        binary_type = filetype.guess(binary_path)
                                        if (
                                            binary_type is not None
                                            and binary_type.extension == "elf"
                                        ):
                                            binary_paths.append(binary_path)
                                    else:
                                        src = os.path.basename(binary_path)
                                        dest = os.path.basename(
                                            os.readlink(binary_path)
                                        )
                                        if src != dest:
                                            # kb.sym_links[src] = dest
                                            pass
        return binary_paths

    def extract(self, origin_path, to_path) -> List[Binary]:
        origin_type = filetype.guess(origin_path)
        binary_paths = []
        if origin_type is not None:
            if origin_type.extension == "elf":
                # Case 1: Executable file
                binary_path = shutil.copy(origin_path, to_path)
                binary_paths.append(binary_path)
            else:
                # Case 2: Firmware (archive)
                # Find a proper decompressing function
                decompress_func = getattr(self, f"_decompress_{origin_type.extension}")
                if decompress_func is not None:
                    decompress_func(origin_path, to_path)
                    for root, _, files in os.walk(to_path):
                        for filename in files:
                            firmware_bin_path = os.path.join(root, filename)
                            # Try to extract binaries from firmware via binwalk
                            binary_paths += self.__extract_from_firmware_bin(
                                firmware_bin_path
                            )
                else:
                    l.warning(f"Failed to decompress {origin_path}")
        else:
            # Case 3: Firmware (binary)
            firmware_bin_path = shutil.copy(origin_path, to_path)
            binary_paths = self.__extract_from_firmware_bin(firmware_bin_path)
            if len(binary_paths) == 0:
                l.warning(f"Failed to extract from {origin_path}")
                return []
        return binary_paths
