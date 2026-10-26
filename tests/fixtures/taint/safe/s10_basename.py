import os

from flask import request, send_file


def download():
    name = os.path.basename(request.args["name"])
    return send_file(os.path.join("/srv/files", name))
