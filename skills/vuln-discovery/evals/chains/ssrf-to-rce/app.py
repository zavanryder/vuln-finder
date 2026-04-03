"""
Chain fixture: SSRF -> internal service -> deserialization -> RCE.

Expected chain:
1. /fetch endpoint has SSRF (user-controlled URL)
2. Internal /admin/import endpoint deserializes pickle from request body
3. Attacker uses SSRF to reach internal /admin/import with crafted pickle payload
"""
import pickle
import requests
from flask import Flask, request

app = Flask(__name__)

# Public endpoint: SSRF
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    resp = requests.get(url, timeout=5)
    return resp.text

# Internal endpoint: no auth, insecure deserialization
@app.route("/admin/import", methods=["POST"])
def admin_import():
    data = request.get_data()
    obj = pickle.loads(data)
    return f"Imported: {obj}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
