import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/orders")
def orders():
    customer = request.args.get("customer")
    cur = sqlite3.connect("shop.db").cursor()
    cur.execute("SELECT * FROM orders WHERE customer = '" + customer + "'")
    return str(cur.fetchall())
