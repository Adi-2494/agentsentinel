import requests
from flask import request


def fetch():
    url = request.args.get("url")
    target = url.strip()
    return requests.get(target).text  # SINK ssrf
