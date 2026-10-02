"""Intentionally vulnerable demo app used by CodeGuard's test-suite. Do not deploy."""
import os
import pickle
import subprocess
import hashlib

import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PASSWORD = "Xk9#mQ2vLp8$wZr4"


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/hello")
def hello():
    return render_template_string("Hello " + request.args.get("name"))


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url).text


def load(blob):
    return pickle.loads(blob)


def weak(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def tangled(a, b, c, d):
    if a:
        if b:
            for i in range(10):
                if c:
                    while d:
                        if i > 3 and a or b:
                            try:
                                d -= 1
                            except Exception:
                                pass
    elif b and c:
        return 1
    elif c or d:
        return 2
    return 0


if __name__ == "__main__":
    app.run(debug=True)
