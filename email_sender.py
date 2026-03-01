import os
import resend
from dotenv import load_dotenv

load_dotenv()

resend.api_key = os.getenv("RESEND_API_KEY")
FROM_EMAIL = f"TeamUp <{os.getenv('RESEND_FROM_EMAIL')}>"

def send_email(recipient_email, subject, body):
    resend.Emails.send({
        "from": FROM_EMAIL,
        "to": recipient_email,
        "subject": subject,
        "text": body
    })
