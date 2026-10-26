import os


def default_dir():
    return "/tmp"


def listing():
    os.system("ls " + default_dir())
