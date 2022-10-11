import argparse
import pathlib

from utils.config import config
from utils.extractor import extract

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', 
                        help='load firmware from this path (directory/zip/binary)', 
                        default='input')
    parser.add_argument('-t', '--tmp', 
                        help='store intermediate files to this directory', default='tmp')
    parser.add_argument('-r', '--report', 
                        help='yield analyzing reports to this directory', default='report')
    
    args = parser.parse_args()
    config.input_path = args.input
    config.tmp_dir = args.tmp
    config.report_dir = args.report
    
    for path in [config.input_path, config.tmp_dir, config.report_dir]:
        pathlib.Path(path).mkdir(parents=True, exist_ok=True)
    
    # Stage-1 decompress and extract firmware into binary binary files, 
    # save them to `tmp` dir, and return the paths of binaries to be analyzed
    binary_paths = extract(config.input_path, config.tmp_dir)