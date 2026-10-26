import subprocess

from flask import request


def handler():
    _ = request.args.get("x")
    return subprocess.run("uptime", shell=True)
