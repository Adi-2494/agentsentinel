import os

from flask import request


def handler():
    name = request.args["file"]
    cmd = "cat "
    cmd += name
    os.popen(cmd)  # SINK command
