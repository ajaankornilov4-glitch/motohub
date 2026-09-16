import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
load_dotenv()

def send_otp(email, code):
    provider=os.getenv("EMAIL_PROVIDER","mock").lower()
    if provider=="mock":
        print(f"\n[DEV EMAIL] {email}: {code}\n")
        return

    host=os.getenv("SMTP_HOST")
    port=int(os.getenv("SMTP_PORT","587"))
    user=os.getenv("SMTP_USER")
    password=os.getenv("SMTP_PASS")
    sender=os.getenv("EMAIL_FROM", user)
    secure=os.getenv("SMTP_SECURE","false").lower()=="true"

    if not host or not user or not password:
        raise RuntimeError("SMTP_HOST, SMTP_USER and SMTP_PASS must be configured")

    msg=EmailMessage()
    msg["Subject"]="MotoHub — код подтверждения"
    msg["From"]=sender
    msg["To"]=email
    msg.set_content(
        f"Ваш код MotoHub: {code}\n\n"
        "Код действует 10 минут. Если вы не запрашивали код, проигнорируйте письмо."
    )

    if secure:
        with smtplib.SMTP_SSL(host, port) as s:
            s.login(user,password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port) as s:
            s.starttls()
            s.login(user,password)
            s.send_message(msg)
