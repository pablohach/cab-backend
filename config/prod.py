# config/prod.py

from .default import *

# Generar SECRET_KEY
# import secrets
# secrets.token_hex(16)

SECRET_KEY = 'd897945374804d64974ee090c48fa5b8'
JWT_SECRET_KEY = 'fbb30b163c1c45a8a35eaed872c21dd0'

APP_ENV = APP_ENV_PRODUCTION
LOG_TO_FILE = True

SQLALCHEMY_DATABASE_URI = 'firebird://SYSDBA:203001@localhost/d:/desa/delphi/proyectos/cab/bases/CAB_DESA.FDB '


# Mail configuration
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USERNAME = 'software.piedrasblancas@gmail.com'
MAIL_PASSWORD = 'zyjhpawfywexolwg'
DONT_REPLY_FROM_EMAIL = '(Sistemas, software.piedrasblancas@gmail.com)'
ADMINS = ('software.piedrasblancas@gmail.com', )
MAIL_USE_TLS = True


# Factura electrónica
FE_DEBUG = False
FE_URL_WSAA = 'https://wsaa.afip.gov.ar/ws/services/LoginCms?wsdl'
FE_URL_WSFEV1 = 'https://servicios1.afip.gov.ar/wsfev1/service.asmx?WSDL'
