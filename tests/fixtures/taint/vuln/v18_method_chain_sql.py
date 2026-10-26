import sqlite3

from flask import request


def find():
    name = request.form.get("name", "").lower()
    conn = sqlite3.connect("db")
    cur = conn.cursor()
    cur.executemany("DELETE FROM t WHERE n = '" + name + "'", [])  # SINK sql
