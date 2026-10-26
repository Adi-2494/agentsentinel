import os

from flask import request, send_file

BASE = "/srv/files"


def download():
    name = request.args["name"]
    full = os.path.join(BASE, name)
    return send_file(full)  # SINK path
