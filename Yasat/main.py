import pathlib

from .utils.extractor import Extractor
from . import config, init_loggers, l, kb

def main(input, tmp, report, log):
    
    # Set up configuration and create necessary directaries
    config.input_path = input
    config.tmp_dir = tmp
    config.report_dir = report
    config.log_dir = log
    
    for path in [config.tmp_dir, config.report_dir, config.log_dir]:
        pathlib.Path(path).mkdir(parents=True, exist_ok=True)
    
    # Initialize logger
    init_loggers()
    
    # Stage-1: Load valid input file. Valid file types inclues:
    # - Firmware (archive), e.g., Archer AX10(US)_V1.20_220117.zip)
    # - Firmware (binary), e.g., ax10v1.20-up-ver1-2-5-P1[20220117-rel52085]_2022-01-17_14.29.24.bin)
    # - Executable file, e.g., hostapd, libcurl.so.4
    # Save the extracted files to `tmp` directory, and return a list of binaries to be analyzed
    l.info('Stage-1: Extract firmware')
    binaries = Extractor().extract(config.input_path, config.tmp_dir)
    
    l.debug(str(kb.sym_links))
    for binary in binaries:
        print(binary.binary_path)
        