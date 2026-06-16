# Intentionally vulnerable Flask app for OSWE auditor validation. DO NOT DEPLOY.
import os

from flask import Flask, request, session, render_template_string

app = Flask(__name__)
# Session key from the environment only — keep the intended bypass SINGULAR (the is_admin
# mass-assignment below), not a second forgeable-session path via a hardcoded SECRET_KEY.
app.secret_key = os.environ.get("FLASK_SECRET_KEY")


@app.post("/login")
def login():
    body = request.get_json(force=True) or {}
    # VULN (step 1 - broken access control / mass assignment): the admin flag is taken
    # straight from the client request body and trusted.
    session["admin"] = bool(body.get("is_admin"))
    session["user"] = body.get("user", "")
    return {"ok": True, "admin": session["admin"]}


@app.route("/render", methods=["GET", "POST"])
def render():
    if not session.get("admin"):
        return ("Forbidden", 403)
    tpl = request.values.get("tpl", "")
    # VULN (step 2 - SSTI -> RCE): an attacker-controlled string is rendered AS a Jinja2
    # template, so `{{ ''.__class__.__mro__[1].__subclasses__() ... }}` reaches os/subprocess.
    return render_template_string(tpl)


if __name__ == "__main__":
    app.run()
