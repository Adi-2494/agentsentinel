import os

from flask import request


def get_param(name):
    return request.args.get(name, "")


def listing():
    folder = get_param("dir")
    os.system("ls " + folder)  # SINK command
