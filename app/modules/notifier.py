import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import os

logger = logging.getLogger(__name__)

def send_email(
    to_email: str,
    subject: str,
    body: str,
    html_body: str = None,
    smtp_server: str = None,
    smtp_port: int = 587,
    smtp_username: str = None,
    smtp_password: str = None,
    from_email: str = None
):
    """Sends an email notification."""
    
    smtp_server = smtp_server or os.getenv('SMTP_SERVER')
    smtp_port = smtp_port or int(os.getenv('SMTP_PORT', 587))
    smtp_username = smtp_username or os.getenv('SMTP_USERNAME')
    smtp_password = smtp_password or os.getenv('SMTP_PASSWORD')
    from_email = from_email or os.getenv('FROM_EMAIL', 'redteam-agent@example.com')

    if not all([smtp_server, smtp_username, smtp_password]):
        logger.error("SMTP server, username, or password not configured. Email not sent.")
        return False

    msg = MIMEMultipart("alternative")
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))
    if html_body:
        msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}", exc_info=True)
        return False
