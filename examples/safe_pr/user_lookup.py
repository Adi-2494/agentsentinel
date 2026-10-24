import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def lookup():
    uid = request.args.get("id", type=int)
    conn = sqlite3.connect("app.db")
    rows = conn.execute("SELECT name FROM users WHERE id = ?", (uid,)).fetchall()
    return {"users": rows}
