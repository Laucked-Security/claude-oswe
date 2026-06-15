# Hardened Flask app (negative fixture). DO NOT DEPLOY.
import os

from flask import Flask, request, session, render_template_string

app = Flask(__name__)
# Session key from the environment only — NO hardcoded SECRET_KEY (a literal one is forgeable in
# white-box, which would itself be a session-forgery auth bypass).
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

# Safe: admin credentials come from the ENVIRONMENT only — there is NO hardcoded/default secret in the
# source (a white-box reader cannot recover them). If they are not configured, deny.
_ADMIN_USER = os.environ.get("ADMIN_USER")
_ADMIN_PASS = os.environ.get("ADMIN_PASS")


@app.post("/login")
def login():
    body = request.get_json(force=True) or {}
    user = str(body.get("user", ""))
    password = str(body.get("pass", ""))
    # Deny unless server-side credentials are configured; the role is never taken from the client body.
    session["admin"] = bool(_ADMIN_USER) and bool(_ADMIN_PASS) and user == _ADMIN_USER and password == _ADMIN_PASS
    session["user"] = user
    return {"ok": True, "admin": session["admin"]}


@app.route("/render", methods=["GET", "POST"])
def render():
    if not session.get("admin"):
        return ("Forbidden", 403)
    name = request.values.get("name", "")
    # Safe: the template is a FIXED literal; user input is DATA passed to the context (autoescaped),
    # never the template source. No SSTI.
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)


if __name__ == "__main__":
    app.run()
