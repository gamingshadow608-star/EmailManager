"""Utility functions to interact with IMAP and SMTP servers.

These helpers hide the details of connecting to a mail server and
parsing messages.  They rely on the standard `imaplib` and `smtplib`
libraries included with Python.  The `email` package is used to
construct and parse MIME messages.

All functions raise exceptions if an error occurs; callers should
handle these appropriately.
"""

from __future__ import annotations

import imaplib
import smtplib
import email
from email.header import decode_header
from email.message import EmailMessage
from typing import List, Dict, Tuple


def _decode_header_value(value: str) -> str:
    """Decode an email header into a readable string.

    Many email headers may be encoded using MIME encoding.  This helper
    decodes those parts and joins them into a single text string.
    """
    parts = decode_header(value)
    decoded_parts = []
    for part, encoding in parts:
        if isinstance(part, bytes):
            decoded_parts.append(part.decode(encoding or "utf-8", errors="ignore"))
        else:
            decoded_parts.append(part)
    return "".join(decoded_parts)


def fetch_unread_summaries(
    imap_server: str,
    imap_port: int,
    username: str,
    password: str,
    max_count: int = 5,
) -> List[Dict[str, str]]:
    """Return a list of summaries of unread messages from the inbox.

    Each summary is a dictionary containing the following keys:
    * `uid`: the IMAP UID of the message (used to fetch full details).
    * `from`: the display name and address of the sender.
    * `subject`: the subject line, decoded.
    * `snippet`: the first 100 characters of the plain‑text body.

    Messages are returned in descending order of date (newest first).  At
    most `max_count` messages are returned.
    """
    msgs: List[Dict[str, str]] = []
    with imaplib.IMAP4_SSL(imap_server, imap_port) as imap:
        imap.login(username, password)
        imap.select("INBOX")
        # Search for unseen messages
        typ, data = imap.search(None, "UNSEEN")
        if typ != "OK":
            return msgs
        ids = data[0].split()
        # Fetch the most recent N IDs (last ones in list)
        recent_ids = ids[-max_count:][::-1]  # reverse for newest first
        for uid in recent_ids:
            typ, msg_data = imap.fetch(uid, "(RFC822)")
            if typ != "OK" or not msg_data:
                continue
            raw_email = msg_data[0][1]
            message = email.message_from_bytes(raw_email)
            from_header = _decode_header_value(message.get("From", ""))
            subject_header = _decode_header_value(message.get("Subject", ""))
            # Get snippet from body
            snippet = ""
            if message.is_multipart():
                for part in message.walk():
                    content_type = part.get_content_type()
                    disposition = part.get("Content-Disposition", "")
                    if content_type == "text/plain" and "attachment" not in disposition:
                        try:
                            body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                        except Exception:
                            body = ""
                        snippet = body.strip().replace("\n", " ")[:100]
                        break
            else:
                try:
                    body = message.get_payload(decode=True).decode(message.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    body = ""
                snippet = body.strip().replace("\n", " ")[:100]
            msgs.append({
                "uid": uid.decode() if isinstance(uid, bytes) else str(uid),
                "from": from_header,
                "subject": subject_header,
                "snippet": snippet,
            })
    return msgs


def fetch_message(
    imap_server: str,
    imap_port: int,
    username: str,
    password: str,
    uid: str,
) -> Dict[str, str]:
    """Fetch the full content of a message by UID.

    Returns a dictionary with `from`, `to`, `subject`, `date` and
    `body` fields.  The body is returned as plain text; HTML parts are
    ignored.
    After fetching, the message is marked as read (seen) on the server.
    """
    with imaplib.IMAP4_SSL(imap_server, imap_port) as imap:
        imap.login(username, password)
        imap.select("INBOX")
        typ, msg_data = imap.fetch(uid, "(RFC822)")
        if typ != "OK" or not msg_data:
            raise RuntimeError("Could not fetch message")
        raw_email = msg_data[0][1]
        message = email.message_from_bytes(raw_email)
        # Mark as seen
        imap.store(uid, "+FLAGS", "(\\Seen)")
        def get_first_text(msg: email.message.Message) -> str:
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    disposition = part.get("Content-Disposition", "")
                    if content_type == "text/plain" and "attachment" not in disposition:
                        try:
                            return part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                        except Exception:
                            continue
                return ""
            else:
                try:
                    return msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    return ""
        return {
            "from": _decode_header_value(message.get("From", "")),
            "to": _decode_header_value(message.get("To", "")),
            "subject": _decode_header_value(message.get("Subject", "")),
            "date": _decode_header_value(message.get("Date", "")),
            "body": get_first_text(message),
        }


def send_email(
    smtp_server: str,
    smtp_port: int,
    username: str,
    password: str,
    recipients: List[str],
    subject: str,
    body: str,
) -> None:
    """Send an email via SMTP.

    This helper builds a simple plain‑text message and sends it to
    recipients using a secure SSL connection.  If the server uses
    STARTTLS instead of SSL, set the port accordingly and modify this
    function to use `SMTP.starttls()` instead.
    """
    msg = EmailMessage()
    msg["From"] = username
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
        server.login(username, password)
        server.send_message(msg)