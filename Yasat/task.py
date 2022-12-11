from .util.extractor import Extractor
from . import l
import angr

class Task:
    
    def __init__(self, config):
        self.config = config
    
    def run(self):
        # Stage-1: Load valid input file. Valid file types inclues:
        # - Firmware (archive), e.g., Archer AX10(US)_V1.20_220117.zip)
        # - Firmware (binary), e.g., ax10v1.20-up-ver1-2-5-P1[20220117-rel52085]_2022-01-17_14.29.24.bin)
        # - Executable file, e.g., hostapd, libcurl.so.4
        # Save the extracted files to `tmp` directory, and return a list of binaries to be analyzed
        l.info('*** Stage 1 - Extract firmware image ***')
        binaries = Extractor().extract(self.config.input_path, self.config.tmp_dir)
        
        for binary in binaries:
            print(binary.binary_path)
        