import subprocess

from flask import request


def handler():
    branch = request.args["b"]
    subprocess.run(["git", "checkout", "--", branch])
