import ast

from flask import request


def calc():
    return str(ast.literal_eval(request.json["expr"]))
