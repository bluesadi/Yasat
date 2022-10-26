import argparse
from Yasat import main

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', 
                        help='load the firmware to be analyzed from this path')
    parser.add_argument('-t', '--tmp', 
                        help='store temporary files to this directory', default='tmp')
    parser.add_argument('-r', '--report', 
                        help='generate analysis reports to this directory', default='report')
    parser.add_argument('-l', '--log', 
                        help='store log messages to this directory', default='log')
    args = parser.parse_args()
    
    main.main(args.input, args.tmp, args.report, args.log)
    