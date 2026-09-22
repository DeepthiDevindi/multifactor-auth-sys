import os
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


def send_verification_email(recipient: str, code: str) -> None:
    host = os.getenv("SMTP_HOST")
    username = os.getenv("SMTP_USERNAME")
    password = (os.getenv("SMTP_PASSWORD") or "").replace(" ", "")
    sender = os.getenv("SMTP_FROM") or username
    if not host or not sender:
        raise RuntimeError("Email delivery is not configured. Set SMTP_HOST and SMTP_FROM in backend/.env.")

    port = int(os.getenv("SMTP_PORT", "587"))
    message = EmailMessage()
    message["Subject"] = "Your Cryptix verification code"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Your Cryptix verification code is {code}. It expires in 10 minutes and can be used only once.\n\n"
        "If you did not request this code, you can ignore this email."
    )

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.starttls(context=context)
            if username and password:
                smtp.login(username, password)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as error:
        raise RuntimeError("The verification email could not be sent. Check the SMTP settings and try again.") from error