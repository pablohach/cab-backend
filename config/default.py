from os.path import abspath, dirname, join

# Define the application directory
BASE_DIR = dirname(dirname(abspath(__file__)))


SYSTEM_NAME = 'Club Andino Bariloche'

SECRET_KEY = 'd1bac422dd7f22b3a7040af5d93f93fb'
JWT_SECRET_KEY = '17cee9b258e05e063c61e1c886156d42'

# Para propagar las excepciones y poder manejarlas a nivel de aplicación.
PROPAGATE_EXCEPTIONS = True

# Database configuration
# URI de la base de datos, se pisa en configuraciones posteriores
SQLALCHEMY_DATABASE_URI = ''
# Se desactiva como indica la documentación
SQLALCHEMY_TRACK_MODIFICATIONS = False
# Se deshabilitan los mensajes de log de SQLAlchemy
SHOW_SQLALCHEMY_LOG_MESSAGES = False

# Deshabilita las sugerencias de otros endpoints relacionados con alguno que no exista (Flask-Restful).
ERROR_404_HELP = False

# App environments
APP_ENV_LOCAL = 'local'
APP_ENV_TESTING = 'testing'
APP_ENV_DEVELOPMENT = 'development'
APP_ENV_STAGING = 'staging'
APP_ENV_PRODUCTION = 'production'
APP_ENV = ''

# Mail configuration
# completar en dev y prod
MAIL_SERVER = ''
MAIL_PORT = 587
MAIL_USERNAME = ''
MAIL_PASSWORD = ''
DONT_REPLY_FROM_EMAIL = ''
REPLY_TO_EMAIL = ''
ADMINS = ()
MAIL_USE_TLS = True


LOG_TO_STDOUT = False
LOG_TO_FILE = False


TOKEN_EXPIRATION_HOURS = 12

# Roles que no dejo modificar/borrar (Admin, Super, User)
FIXED_ROLES = 3



# Factura electrónica
FE_DEBUG = True
FE_TIMEOUT = 300
FE_FMT_EMPRESA_PTO_VTA = '{:02d}/{:04d}'
FE_URL_WSAA = 'https://wsaahomo.afip.gov.ar/ws/services/LoginCms?wsdl'
FE_URL_WSFEV1 = 'https://wswhomo.afip.gov.ar/wsfev1/service.asmx?WSDL'
FE_PATH = join(BASE_DIR, 'fiscal/fe')
FE_CACHE_PATH = join(FE_PATH, 'cache')
# uso un directorio de cache por cada empresa-punto de venta
FE_CACHE_FMT_PATH = FE_CACHE_PATH + '/' + FE_FMT_EMPRESA_PTO_VTA

FE_PDFS_PATH = join(FE_PATH, 'pdfs')
FE_TEMPLATES_PATH = join(FE_PATH, 'templates')
# FE_AUTH_PATH: Aqui estaran los certificados
# dentro de este un directorio por cada empresa-punto de venta (01/0012 por ejemplo)
# y dentro de ese directorio se usara FE_AUTH_CERT_NAME y FE_AUTH_PRIVATEKEY_NAME
FE_AUTH_PATH = join(FE_PATH, 'auth')
FE_AUTH_CERT_NAME = 'certificado.crt'
FE_AUTH_PRIVATEKEY_NAME = 'clave_privada.key'
