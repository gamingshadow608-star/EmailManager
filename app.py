"""Main Flask application for the email bot.

This module defines the web interface and routes for the email bot.
Users can log in, manage their email credentials, read and send
messages, and review logs.  Administrators can create new accounts and
assign roles.

Run this script to start the development server.  Command‑line
arguments are available for initial setup:

```
python app.py --initdb --create-admin
```

"""

from __future__ import annotations

import os
import click
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps

import models
import email_utils


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key")

# Make models accessible in templates
@app.context_processor
def inject_models():
    return dict(models=models)


def login_required(f):
    """Decorator to require a logged‑in user."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require the current user to be an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id or models.get_user_role(user_id) != "admin":
            flash("You do not have permission to access this page.")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
@login_required
def index():
    """Home page displaying unread email summaries and logs."""
    user_id = session["user_id"]
    # Get email account config
    account = models.get_email_account(user_id)
    summaries = []
    error = None
    if account:
        try:
            summaries = email_utils.fetch_unread_summaries(
                account["imap_server"],
                account["imap_port"],
                account["username"],
                account["password"],
                max_count=5,
            )
        except Exception as e:
            error = f"Could not fetch messages: {e}"
    logs = models.get_logs(user_id=user_id, limit=10)
    return render_template(
        "dashboard.html",
        account=account,
        summaries=summaries,
        logs=logs,
        error=error,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user_id = models.verify_user(username, password)
        if user_id:
            session.clear()
            session["user_id"] = user_id
            session["username"] = username
            models.add_log(user_id, f"User {username} logged in")
            return redirect(url_for("index"))
        flash("Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Log out the current user."""
    user_id = session.get("user_id")
    username = session.get("username")
    if user_id:
        models.add_log(user_id, f"User {username} logged out")
    session.clear()
    return redirect(url_for("login"))


@app.route("/connect", methods=["GET", "POST"])
@login_required
def connect():
    """Page to add or update email account details."""
    user_id = session["user_id"]
    current = models.get_email_account(user_id)
    if request.method == "POST":
        email_address = request.form.get("email_address", "").strip()
        imap_server = request.form.get("imap_server", "").strip()
        imap_port = int(request.form.get("imap_port", "993"))
        smtp_server = request.form.get("smtp_server", "").strip()
        smtp_port = int(request.form.get("smtp_port", "465"))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not all([email_address, imap_server, smtp_server, username, password]):
            flash("Please fill in all fields")
        else:
            models.add_email_account(
                user_id,
                email_address,
                imap_server,
                imap_port,
                smtp_server,
                smtp_port,
                username,
                password,
            )
            models.add_log(user_id, f"Updated email account settings for {email_address}")
            flash("Email account saved")
            return redirect(url_for("index"))
    return render_template("connect.html", current=current)


@app.route("/message/<uid>")
@login_required
def message(uid: str):
    """Display a full email message."""
    user_id = session["user_id"]
    account = models.get_email_account(user_id)
    if not account:
        flash("You need to connect your email account first")
        return redirect(url_for("index"))
    try:
        msg = email_utils.fetch_message(
            account["imap_server"],
            account["imap_port"],
            account["username"],
            account["password"],
            uid,
        )
        models.add_log(user_id, f"Read message {uid}")
        return render_template("message.html", msg=msg)
    except Exception as e:
        flash(f"Could not fetch message: {e}")
        return redirect(url_for("index"))


@app.route("/send", methods=["GET", "POST"])
@login_required
def send_mail():
    """Compose and send a new email."""
    user_id = session["user_id"]
    account = models.get_email_account(user_id)
    if not account:
        flash("You need to connect your email account first")
        return redirect(url_for("index"))
    if request.method == "POST":
        to_addrs = request.form.get("to", "").strip()
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()
        if not to_addrs or not subject or not body:
            flash("All fields are required")
        else:
            recipients = [addr.strip() for addr in to_addrs.split(",") if addr.strip()]
            try:
                email_utils.send_email(
                    account["smtp_server"],
                    account["smtp_port"],
                    account["username"],
                    account["password"],
                    recipients,
                    subject,
                    body,
                )
                models.add_log(user_id, f"Sent email to {', '.join(recipients)}")
                flash("Email sent successfully")
                return redirect(url_for("index"))
            except Exception as e:
                flash(f"Failed to send email: {e}")
    return render_template("send.html")


@app.route("/logs")
@login_required
def logs_view():
    """Display recent logs.  Admins see all logs; normal users see their own."""
    user_id = session["user_id"]
    role = models.get_user_role(user_id)
    if role == "admin":
        logs = models.get_logs(user_id=None, limit=50)
    else:
        logs = models.get_logs(user_id=user_id, limit=50)
    return render_template("logs.html", logs=logs)


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@admin_required
def manage_users():
    """Admin page to manage user accounts."""
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            new_username = request.form.get("new_username", "").strip()
            new_password = request.form.get("new_password", "")
            new_role = request.form.get("new_role", "user")
            if not new_username or not new_password:
                flash("Please provide a username and password for the new user")
            elif models.get_user_by_username(new_username):
                flash("A user with that username already exists")
            else:
                models.create_user(new_username, new_password, new_role)
                models.add_log(session["user_id"], f"Created user {new_username} with role {new_role}")
                flash("User created")
        elif action == "update_role":
            user_id = int(request.form.get("user_id"))
            role = request.form.get("role", "user")
            models.set_user_role(user_id, role)
            models.add_log(session["user_id"], f"Changed role for user {user_id} to {role}")
            flash("Role updated")
        elif action == "delete":
            user_id = int(request.form.get("user_id"))
            # Do not allow deleting yourself
            if user_id == session["user_id"]:
                flash("You cannot delete yourself")
            else:
                models.delete_user(user_id)
                models.add_log(session["user_id"], f"Deleted user {user_id}")
                flash("User deleted")
    users = models.get_all_users()
    return render_template("admin_users.html", users=users)


@click.command()
@click.option('--initdb', is_flag=True, help='Initialise the database')
@click.option('--create-admin', is_flag=True, help='Create an administrator account')
def main(initdb: bool, create_admin: bool):
    """Command‑line entry point."""
    if initdb:
        models.init_db()
        click.echo("Database initialised")
    if create_admin:
        # Prompt for credentials
        username = click.prompt("Admin username")
        password = click.prompt("Admin password", hide_input=False, confirmation_prompt=True)
        if models.create_user(username, password, role="admin"):
            click.echo(f"Created admin user {username}")
        else:
            click.echo("User already exists")
    if not initdb and not create_admin:
        # run server
        app.run(debug=True, port=5000)


if __name__ == "__main__":
    main()
