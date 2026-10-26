import os

from flask import request


def read_arg():
    return request.args.get("x")


def build(cmd_part):
    return "echo " + cmd_part


def handler():
    os.system(build(read_arg()))  # SINK command
