import subprocess

from flask import request


def run(cmd):
    return subprocess.run(cmd, shell=True)


def handler():
    run(request.form["cmd"])  # SINK command
