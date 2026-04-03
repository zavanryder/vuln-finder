"""Vulnerable: SSRF via user-controlled URL in requests.get."""
import requests
from flask import Flask, request as req

app = Flask(__name__)

@app.route("/fetch")
def fetch_url():
    url = req.args.get("url")
    resp = requests.get(url)
    return resp.text

@app.route("/proxy")
def proxy():
    target = req.args.get("target")
    resp = requests.get(f"http://{target}/api/data")
    return resp.json()
