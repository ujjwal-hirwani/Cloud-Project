import resend
import os
resend.api_key = os.getenv("RESEND_API_KEY")

resend.Emails.send({
    "from": "onboarding@ujjwalhirwani.me",
    "to": "durgahirwani70@gmail.com",
    "subject": "Resend works",
    "text": "This confirms the API key is valid."
})
