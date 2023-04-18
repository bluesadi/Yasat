import os
import sys

from .misc.api_scanner import scan
from .task import Task

def main_dev():
    argv = sys.argv
    if len(argv) <= 1:
        os.system("yasat -c config_dev.yml -p 10")
    else:
        command = argv[1]
        if command == "apiscan":
            scan(argv[2])