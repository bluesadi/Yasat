import os
import sys

if __name__ == '__main__':
    os.system(f'python run.py -c tests/test_{sys.argv[1]}/config.yml')