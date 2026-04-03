"""Safe: Path traversal -- resolved path checked against base directory."""
import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
UPLOAD_DIR = os.path.realpath("/var/uploads")

@app.route("/download")
def download():
    filename = request.args.get("file")
    filepath = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    if not filepath.startswith(UPLOAD_DIR + os.sep):
        abort(403)
    return send_file(filepath)
