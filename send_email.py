import os
import smtplib
import ssl
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

# Obtén las credenciales desde un archivo .env
email_sender = os.environ.get('EMAIL_SENDER')
email_password = os.environ.get("EMAIL_PASSWORD")
email_receiver = os.environ.get('EMAIL_RECEIVER')

def send_email(subject, body, attachment_path=None):
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body)

    if attachment_path:
        with open(attachment_path, 'rb') as f:
            file_data = f.read()
            file_name = os.path.basename(attachment_path)
            em.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=file_name)

    # Usar SSL para enviar el correo
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())