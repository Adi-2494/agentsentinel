from flask import request


def handler():
    opts = {"path": request.args["p"], "mode": "r"}
    return open(opts["path"]).read()  # SINK path
