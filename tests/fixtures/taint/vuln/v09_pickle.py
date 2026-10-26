import pickle

from flask import request


def load():
    return pickle.loads(request.data)  # SINK deserialization
