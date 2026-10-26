import requests
from flask import request

ALLOWED = {"a": "https://api.example.com/a", "b": "https://api.example.com/b"}


def fetch():
    key = request.args["k"]
    return requests.get(ALLOWED.get(key, ALLOWED["a"])).text
