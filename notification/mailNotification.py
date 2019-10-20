# using SendGrid's Python Library
# https://github.com/sendgrid/sendgrid-python
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


def mail_notification():
    message = Mail(
        from_email='mcloving12345@gmail.com',
        to_emails='nnbaokhang@gmail.com',
        subject='Sending with Twilio SendGrid is Fun',
        html_content='<strong>and easy to do anywhere, even with Python</strong>')
    try:
        sg = SendGridAPIClient('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')
        response = sg.send(message)
        print(response)
    except Exception as e:
        print(e)