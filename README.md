# Email Bot Application

This project provides a web‑based email bot that allows multiple users to connect to their email accounts, read and send messages, and review activity logs.  It is written in **Python 3** using the **Flask** framework and uses **Bootstrap** for styling.  A small SQLite database stores user accounts and action logs.

## Features

* **User management:**
  * Each person has a username, password and assigned role (`user` or `admin`).
  * Administrators can add new accounts and change roles.
  * Passwords are stored hashed with **bcrypt** for security.
* **Email account connection:**
  * After logging into the web app you can enter your email address and IMAP/SMTP credentials.  The bot uses these details to fetch messages and send new mail.
  * The credentials are stored encrypted in the database using a simple Fernet key; you may supply your own secret key via the `EMAIL_BOT_SECRET` environment variable.
* **Reading mail:**
  * The home page lists the five most recent unread messages from the inbox.  For each message it shows the sender, subject, and a short snippet of the body.
  * Clicking a message expands it and marks it as read.  All actions are logged.
* **Sending mail:**
  * There is a compose form allowing you to send a new email through your connected account.  You can add recipients, a subject line and a body.
  * After sending, the bot records the action in the log.
* **Activity log:**
  * Every important operation (login, logout, reading a message, sending an email, admin actions) is recorded with the user name, timestamp and description.
  * Users can view their own recent activity; administrators can see all logs.
* **Responsive interface:**
  * Templates use **Bootstrap** classes for a simple responsive layout.  No inline CSS is used.

## Running the application

### Prerequisites

* Python 3.8 or newer
* The `virtualenv` tool (optional but recommended)
* Access to an IMAP/SMTP server (for example Gmail, Outlook or another mail provider)

### Installation

Clone or extract this repository and then install the dependencies:

```bash
cd email_bot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configuration

The app uses a secret key for session management and for encrypting email credentials.  You should define the following environment variables before running the server:

```bash
export FLASK_SECRET_KEY="a_random_long_secret_key"
export EMAIL_BOT_SECRET="another_secret_key_used_for_encryption"
```

The first time you run the app there will be no accounts.  Use the following command to initialise the database and create an initial administrator:

```bash
python app.py --initdb --create-admin
```

You will be asked to supply a username and password for the admin account.  After that the server can be started normally.

### Running the server

```bash
python app.py
```

By default the app runs on `http://127.0.0.1:5000/`.  Use your browser to visit that address and log in with the credentials you created earlier.  From there you can connect your email account and begin reading and sending messages.

## Security notes

This program is intended as a demonstration and **should not be used in production without review**.  In particular:

* Email account passwords are encrypted in the database using a symmetric key derived from the `EMAIL_BOT_SECRET` environment variable.  Make sure to set a strong secret and protect it.
* The web application uses Flask’s development server.  For a production deployment you should run behind a proper WSGI server (for example Gunicorn) and enable HTTPS.
* The IMAP/SMTP credentials are stored at rest; ensure your environment has adequate disk security.
* Consider implementing OAuth authentication with the email provider rather than storing credentials directly.

## Licence

This project is provided for educational purposes and comes with no warranty.