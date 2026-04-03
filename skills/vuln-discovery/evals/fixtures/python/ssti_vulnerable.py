"""Vulnerable: Server-side template injection via Jinja2."""
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    template = Template("Hello " + name + "!")
    return template.render()

@app.route("/preview")
def preview():
    from flask import render_template_string
    tpl = request.args.get("template", "default")
    return render_template_string(tpl)
