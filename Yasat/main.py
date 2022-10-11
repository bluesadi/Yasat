import argparse
import pathlib

from utils.config import config
from utils.extractor import Extractor

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', 
                        help='load firmware from this path', 
                        default='input')
    parser.add_argument('-t', '--tmp', 
                        help='store temporary files to this directory', default='tmp')
    parser.add_argument('-r', '--report', 
                        help='generate analysis reports to this directory', default='report')
    
    args = parser.parse_args()
    config.input_path = args.input
    config.tmp_dir = args.tmp
    config.report_dir = args.report
    
    for path in [config.tmp_dir, config.report_dir]:
        pathlib.Path(path).mkdir(parents=True, exist_ok=True)
        
    # Stage-1: Load valid input file. Valid file types inclues:
    # - Firmware (archive), e.g., Archer AX10(US)_V1.20_220117.zip)
    # - Firmware (binary), e.g., ax10v1.20-up-ver1-2-5-P1[20220117-rel52085]_2022-01-17_14.29.24.bin)
    # - Executable file, e.g., hostapd, libcurl.so.4
    # Save the extracted files to `tmp` directory, and return a list of binaries to be analyzed
    binaries = Extractor().extract(config.input_path, config.tmp_dir)