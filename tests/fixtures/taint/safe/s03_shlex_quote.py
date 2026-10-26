import os
import shlex

from flask import request


def handler():
    name = shlex.quote(request.args["file"])
    os.system("cat " + name)
