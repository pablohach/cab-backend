import os
import logging
import decimal
from logging.handlers import RotatingFileHandler
from flask import Flask, json
from app.db import db
from flask_cors import CORS
from .ext import ma, jwt, mail

from app.common.response import HttpStatusCodes, JsonResponse


# Creo un JSON encoder personalizado, para que soporte decimales
class MyJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            # Convert decimal instances to strings.
            return str(obj)
        return super(MyJSONEncoder, self).default(obj)


# Creo la app
def create_app(settings_module):
    app = Flask(__name__, instance_relative_config=True)

    # NADA DE ESTO, lo manejo desde configuracion nginx
    # app = Flask(__name__, instance_relative_config=True,
    #             static_folder='../vue/assets')
    # ATENCION, tengo que dejar static_folder='../vue/assets' para que funcione el fromtend

    # Load the config file specified by the APP environment variable
    app.config.from_object(settings_module)

    app.json_encoder = MyJSONEncoder

    # Habilito CORS para que se pueda acceder desde otro sitio
    CORS(app, expose_headers=["Content-Disposition"])

    #CORS(app, expose_headers=["Content-Disposition"],  supports_credentials=True)
    #CORS(app, expose_headers=["*"])
    #CORS(app, resources={"/api/*": {"origins": "*"}})

    # Inicializa las extensiones
    db.init_app(app)
    ma.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)

    # Captura todos los errores 404
    #Api(app, catch_all_404s=True)
    # Los atrapo desde la app

    # Deshabilita el modo estricto de acabado de una URL con /
    app.url_map.strict_slashes = False

    # Registra los blueprints
    register_blueprints(app)

    configure_logging(app)

    # Para que no ordene las claves al generar un JSON
    app.config['JSON_SORT_KEYS'] = False

    # Mensaje customizado de jwt
    # Set a callback function to return a custom response whenever an expired
    # token attempts to access a protected route. This particular callback function
    # takes the jwt_header and jwt_payload as arguments, and must return a Flask
    # response. Check the API documentation to see the required argument and return
    # values for other callback functions.

    @jwt.expired_token_loader
    def my_expired_token_callback(jwt_header, jwt_payload):
        return JsonResponse(HttpStatusCodes.UNAUTHORIZED, message="El token ha expirado.", data={'token_expired': True})

    # Filtros para formatear en jinja2

    @app.template_filter()
    def fmt_datetime(value, format='%d/%m/%Y'):
        return value.strftime(format) if value else ""

    @app.template_filter()
    def fmt_importe(value, simbol='$'):
        if isinstance(value, str):
            value = float(value)
        if value or value == 0:
            return (((simbol + " " if simbol else "") + "{:,.2f}").format(value))
        return ""

    return app


def register_blueprints(app):
    # Registra manejadores de errores personalizados
    from app.errors import bp as errors_bp
    app.register_blueprint(errors_bp)

    # Blueprints de API
    from app.auth.api_v1_0.resources import users_v1_0_bp
    app.register_blueprint(users_v1_0_bp)


    from app.test.resources import test_bp
    app.register_blueprint(test_bp)



def configure_logging(app):
    # Niveles: DEBUG, INFO, WARNING, ERROR and CRITICAL

    # Elimina los manejadores por defecto de la app
    del app.logger.handlers[:]

    #loggers = [app.logger, logging.getLogger('sqlalchemy') ]
    # agrego cada modulo mio que quiero que use un logger distinto al de app.logger
    # es mas claro usar loggers distintos por cada modulo que quiero que logee, ya que se sabe bien que modulo es el que logea
    loggers = [app.logger, logging.getLogger('app')]
    handlers = []

    # si esta configurado que salga por consola (en produccion no es necesario, ya que nadie mira consola)
    if app.config['LOG_TO_STDOUT']:
        # Manejador para la consola
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(verbose_formatter())
        console_handler.setLevel(
            logging.INFO if app.config['APP_ENV'] == app.config['APP_ENV_PRODUCTION'] else logging.DEBUG)
        handlers.append(console_handler)

    if app.config['LOG_TO_FILE']:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/CAB.log',
                                           maxBytes=10240, backupCount=10)
        file_handler.setFormatter(verbose_formatter())
        file_handler.setLevel(logging.INFO)
        handlers.append(file_handler)

    # Para cada logger definido, le agrego los manejadores definidos
    for l in loggers:
        for handler in handlers:
            l.addHandler(handler)
        l.propagate = False
        l.setLevel(logging.DEBUG)

    if app.config['APP_ENV'] == app.config['APP_ENV_PRODUCTION']:
        app.logger.info('CAB API startup')


def verbose_formatter():
    return logging.Formatter(
        '[%(asctime)s.%(msecs)d]\t %(levelname)s \t[%(name)s.%(funcName)s:%(lineno)d]\t %(message)s',
        datefmt='%d/%m/%Y %H:%M:%S'
    )
