import os

from flask import request


def handler():
    n = int(request.args["n"])
    os.system(f"seq {n}")
