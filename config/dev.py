# config/dev.py

from .default import *


APP_ENV = APP_ENV_DEVELOPMENT

LOG_TO_STDOUT = True
LOG_TO_FILE = False


SQLALCHEMY_DATABASE_URI = 'firebird://SYSDBA:203001@localhost/d:/desa/delphi/proyectos/cab/bases/CAB_DESA.FDB '
# SQLALCHEMY_ECHO = True # para que imprima todos los querys


# Mail configuration
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USERNAME = 'tu correo'
MAIL_PASSWORD = 'tu contraseña'
DONT_REPLY_FROM_EMAIL = '(Juanjo, juanjo@j2logo.com)'
ADMINS = ('juanjo@j2logo.com', )
MAIL_USE_TLS = True


TOKEN_EXPIRATION_HOURS = 1
