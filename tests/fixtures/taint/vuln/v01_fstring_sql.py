import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {uid}"
    return str(sqlite3.connect("db").execute(query).fetchall())  # SINK sql
