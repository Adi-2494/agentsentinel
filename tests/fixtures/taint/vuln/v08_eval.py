from flask import request


def calc():
    expr = request.json["expr"]
    return str(eval(expr))  # SINK code
