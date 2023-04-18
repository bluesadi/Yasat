import filetype
import zipfile
import os
import shutil
import logging

import binwalk

from ..utils.files import Files
from ..utils.print import PrintUtil

l = logging.getLogger(__name__)


class Extractor:
    """
    Basically dirty work.
    You won't want to dive into it.
    """

    def _decompress_zip(self, path, to_path):
        with zipfile.ZipFile(path, "r") as ref:
            ref.extractall(to_path)

    def _is_file(self, path):
        return not os.path.islink(path) and os.path.isfile(path)

    def _is_elf(self, path):
        if self._is_file(path):
            ftype = filetype.guess(path)
            if ftype is not None:
                return ftype.extension == "elf"
        return False

    def _binwalk(self, src, dst):
        extracted_path = os.path.join(dst, f"_{os.path.basename(src)}.extracted")
        Files.remove(extracted_path)
        # We use this flag to denote that the firmware has been cached
        binwalk.scan(src, signature=True, quiet=True, extract=True, matryoshka=True, depth=2, 
                     directory=dst)
        paths = []
        for dirpath, _, filenames in os.walk(extracted_path):
            if "squashfs-root-0" not in dirpath:
                for filename in filenames:
                    path = os.path.join(dirpath, filename)
                    if self._is_elf(path):
                        paths.append(path)
                    else:
                        Files.remove(path)
        return paths

    def extract(self, src, dst):
        """
        Extract ELF files
        - Try to decompress the input file (if the input file is an archive file, e.g., .zip file).
        - Try to extract ELF executables from the input file (if the input file is a firmware image) or the decompressed
          files.
        - Do nothing if the input file is already an ELF executable.
        - Save all the ELF executable(s) from to `config.tmp_dir` for subsequent procedures.
        """
        if self._is_elf(src):
            # ELF file
            return [shutil.copy(src, dst)]
        # Firmware (binary or archive)
        try:
            return self._binwalk(src, dst)
        except BaseException as e:
            l.error(f"Error occured when extracting ELF files from {src}")
            l.error(PrintUtil.format_exception(e))
        return []