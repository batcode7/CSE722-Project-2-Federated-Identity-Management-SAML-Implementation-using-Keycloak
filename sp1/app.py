import os
import json
import functools
from flask import (
    Flask, render_template, redirect, request, session, url_for,
    send_from_directory, abort, Response
)
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings


# ----- Flask app (explicit folders so it works no matter where you launch from)
BASE = os.path.abspath(os.path.dirname(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE, "templates"),
    static_folder=os.path.join(BASE, "static"),
)
app.secret_key = "dev-only-change-me"   # change for anything public


# ----- Helpers
def _prepare_flask_request():
    """
    Convert Flask request to the dict that python3-saml expects.
    """
    host = request.host
    # derive port part for the SAML dict
    if ":" in host:
        port = host.split(":", 1)[1]
    else:
        port = "443" if request.is_secure else "80"

    return {
        "https": "on" if request.is_secure else "off",
        "http_host": host,
        "server_port": port,
        "script_name": request.path,
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
        "query_string": request.query_string,
    }


def load_settings(choice: str) -> dict:
    """
    Merge base per-IdP settings with the advanced security options.
    choice: 'a' or 'b'
    """
    assert choice in ("a", "b")
    with open(os.path.join(BASE, "advanced_settings.json"), "r", encoding="utf-8") as f:
        adv = json.load(f)
    with open(os.path.join(BASE, f"settings_kc{'A' if choice == 'a' else 'B'}.json"), "r", encoding="utf-8") as f:
        base = json.load(f)

    # Merge in 'security' section from advanced settings
    if "security" in adv:
        base["security"] = adv["security"]
    return base


def build_auth(choice: str) -> OneLogin_Saml2_Auth:
    """
    Create a SAML Auth object for the chosen IdP.
    NOTE: pass the dict as `old_settings=` (or as 2nd positional) — NOT `settings=`.
    """
    saml_settings = load_settings(choice)
    return OneLogin_Saml2_Auth(_prepare_flask_request(), old_settings=saml_settings)


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("choose_idp", next=request.path))
        return view(*args, **kwargs)
    return wrapper


# ----- Routes
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/choose-idp")
def choose_idp():
    nxt = request.args.get("next", "/")
    return render_template("choose_idp.html", next=nxt)


@app.route("/login")
def login():
    choice = request.args.get("idp")  # 'a' or 'b'
    nxt = request.args.get("next", "/")
    if choice not in ("a", "b"):
        return redirect(url_for("choose_idp", next=nxt))

    session["pending_idp"] = choice
    session["post_login_next"] = nxt

    # Set force_authn=True if you want to always show the IdP login page
    auth = build_auth(choice)
    return redirect(auth.login(force_authn=False))


@app.route("/assert/<choice>", methods=["POST"])
def acs(choice):
    """
    Assertion Consumer Service endpoint — receives SAMLResponse.
    """
    if choice not in ("a", "b"):
        abort(404)

    auth = build_auth(choice)
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        return f"ACS errors: {errors} :: {auth.get_last_error_reason()}", 400
    if not auth.is_authenticated():
        return "Not authenticated", 401

    session["user"] = {
        "nameid": auth.get_nameid(),
        "attrs": auth.get_attributes(),
    }
    return redirect(session.pop("post_login_next", url_for("profile")))


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=session["user"])


@app.route("/photo")
@login_required
def photo():
    return send_from_directory(os.path.join(BASE, "static"), "photo.jpg")


@app.route("/logout")
def logout():
    """
    Local logout + redirect to IdP logout. If you know which IdP you used,
    pass ?idp=a or ?idp=b; otherwise we'll reuse the last pending choice.
    """
    choice = request.args.get("idp", session.get("pending_idp", "a"))
    session.clear()
    try:
        return redirect(build_auth(choice).logout())
    except Exception:
        # If IdP logout URL not configured, just return to home
        return redirect(url_for("home"))


@app.route("/metadata")
def metadata():
    """
    Expose SP metadata (use IdP-A settings for SP descriptor).
    NOTE: pass dict as old_settings=, NOT settings=.
    """
    settings = OneLogin_Saml2_Settings(
        old_settings=load_settings("a"),
        sp_validation_only=True
    )
    md = settings.get_sp_metadata()
    errors = settings.validate_metadata(md)
    if errors:
        return f"Metadata errors: {errors}", 500
    return Response(md, mimetype="text/xml")


if __name__ == "__main__":
    # run SP1 on port 5001
    app.run(host="0.0.0.0", port=5001, debug=True)
