"""Vulnerable: Path traversal via user-controlled filename."""
import os
from flask import Flask, request, send_file

app = Flask(__name__)
UPLOAD_DIR = "/var/uploads"

@app.route("/download")
def download():
    filename = request.args.get("file")
    filepath = os.path.join(UPLOAD_DIR, filename)
    return send_file(filepath)

@app.route("/read")
def read():
    path = request.args.get("path")
    with open(path) as f:
        return f.read()
