import os
import sys


def main():
    path = sys.argv[1]
    os.system(f"rm -rf {path}")  # SINK command
