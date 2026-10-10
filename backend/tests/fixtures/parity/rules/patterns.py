"""Every Python pattern rule. Browser scans have no Bandit, so the Bandit-overlap rules stay on."""
import hashlib
import os
import pickle
import subprocess

import jwt
import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
value = eval(expr)
model.eval()
exec(code)
executor.exec_module(mod)
subprocess.run(cmd, shell=True)
subprocess.run(["ls", "-l"])
os.system("ls " + path)
os.popen(cmd)
os.path.join(a, b)
q = f"SELECT * FROM users WHERE id = {uid}"
q2 = "SELECT * FROM users WHERE name = '%s'" % name
q3 = "DELETE FROM sessions WHERE token = '{}'".format(token)
cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
digest = hashlib.md5(data).hexdigest()
etag = hashlib.sha1(body, usedforsecurity=False).hexdigest()
strong = hashlib.sha256(data).hexdigest()
requests.get(url, verify=False)
requests.get(url, verify=True)
app.add_middleware(CORSMiddleware, allow_origins=["*"])
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example"])
app.run(host="0.0.0.0", debug=True)
DEBUG = True
DEBUG = Truthy
claims = jwt.decode(token, verify=False)
claims = jwt.decode(token, key, options={"verify_signature": False})
claims = jwt.decode(token, key, algorithms=["HS256"])
claims = jwt.decode(token, key, algorithms=["none"])
obj = pickle.loads(blob)
obj = pickle.load(fh)
cfg = yaml.load(stream)
cfg = yaml.load(stream, Loader=yaml.SafeLoader)
cfg = yaml.safe_load(stream)
r = requests.get(request.args["url"])
r = requests.post(request.json["hook"])
data = open(request.args["file"]).read()
data = open("static.txt").read()
ratio = total // count
