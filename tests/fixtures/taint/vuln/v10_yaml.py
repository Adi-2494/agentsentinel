import yaml
from flask import request


def load():
    body = request.get_data()
    return yaml.load(body, Loader=yaml.Loader)  # SINK deserialization
