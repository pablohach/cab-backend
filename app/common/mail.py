import logging

from smtplib import SMTPException
from threading import Thread

from flask import current_app
from flask_mail import Message

from app import mail
from app.common.error_handling import AppErrorBaseClass

logger = logging.getLogger(__name__)


def _send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except SMTPException:
            logger.exception("Ocurrió un error al enviar el email")
            raise AppErrorBaseClass("[MAIL SERVER] not working")


def send_email(subject, recipients, text_body, sender=None,
               cc=None, bcc=None, html_body=None, attachments=None):
    """ 
        attachments: list of type Attachment
    """
    sender = sender or current_app.config['DONT_REPLY_FROM_EMAIL']
    msg = Message(subject, sender=sender,
                  recipients=recipients, cc=cc, bcc=bcc, attachments=attachments)

    msg.body = text_body
    if html_body:
        msg.html = html_body
    Thread(target=_send_async_email, args=(
        current_app._get_current_object(), msg)).start()
