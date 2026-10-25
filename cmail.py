
import os
import smtplib
from email.message import EmailMessage

EMAIL_ADDRESS = os.environ["GMAIL_ADDRESS"]
APP_PASSWORD = os.environ["GMAIL_APP_PASSWORD"]


def send_mail(to, body, subject):
    msg = EmailMessage()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_ADDRESS, APP_PASSWORD)
        server.send_message(msg)


def send_user_appointment_email(appointment):
    body = f"""
Hi {appointment['customer_name']},

Your appointment has been APPROVED!

Service: {appointment['service_name']}
Date: {appointment['booking_date']}
Time: {appointment['booking_time']}
Payment Method: {appointment['payment_method']}
Advance Paid: ₹{appointment['advance_amount']}
Remaining: ₹{appointment['remaining_amount']}

Thank you for choosing Lakshmi Makeovers.
"""
    subject = "Your Appointment is Approved"
    send_mail(appointment['customer_email'], body, subject)


def send_user_cancel_email(appointment):
    body = f"""
Hi {appointment['customer_name']},

We regret to inform you that your appointment has been CANCELLED.

Service: {appointment['service_name']}
Date: {appointment['booking_date']}
Time: {appointment['booking_time']}

If you want to reschedule, please book a new appointment.

Thank you,
Lakshmi Makeovers
"""
    subject = "Your Appointment has been Cancelled"
    send_mail(appointment['customer_email'], body, subject)
    