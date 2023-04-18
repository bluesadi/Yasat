import os
import sys

from .misc.api_scanner import scan
from .task import Task

def example():
    os.system("yasat -c examples/config.yml -p 10")