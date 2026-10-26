import os

from flask import request


def handler():
    name = request.args["file"]
    name = "report.txt"
    os.system("cat " + name)
