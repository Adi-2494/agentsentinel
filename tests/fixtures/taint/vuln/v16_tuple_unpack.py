import os

from flask import request


def handler():
    user, cmd = request.args["u"], request.args["c"]
    os.system(cmd)  # SINK command
