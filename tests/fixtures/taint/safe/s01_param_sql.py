import sqlite3

from flask import request


def user():
    uid = request.args.get("id")
    return sqlite3.connect("db").execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall()
