from flask import request, render_template
from app.errors import bp
from app.common.response import JsonResponse
from app.common.error_handling import ObjectNotFound, AppErrorBaseClass, BadRequest, Unauthorized, TokenExpired


import logging
logger = logging.getLogger(__name__)


def wants_json_response():
    return request.accept_mimetypes['application/json'] >= \
        request.accept_mimetypes['text/html']


def MultiResponse(status_code, message=None, data=None):
    if status_code == 500:
        message = message or 'Un error inesperado ha ocurrido.'
        logger.error(message)

    if wants_json_response():
        return JsonResponse(status_code=status_code, message=message, data=data)

    # Es respuesta html
    # , body_class='bg-dark bg-gradient'
    return render_template('errors/base.html', 
                           status_code=status_code,
                           message=message), status_code


# deshabilito para desarrollo, para ver errores
@bp.app_errorhandler(Exception)
def handle_exception_error(e):
    return MultiResponse(500, str(e))


@bp.app_errorhandler(400)
def handle_400_error(e):
    return MultiResponse(400, 'Su cliente ha emitido una solicitud incorrecta o ilegal.')


@bp.app_errorhandler(401)
def handle_401_error(e):
    return MultiResponse(401, str(e))


@bp.app_errorhandler(405)
def handle_405_error(e):
    return MultiResponse(405, 'El método no está permitido para la URL solicitada.')


@bp.app_errorhandler(403)
def handle_403_error(e):
    return MultiResponse(403, str(e))


@bp.app_errorhandler(404)
def handle_404_error(e):
    return MultiResponse(404, 'El endpoint al que intenta acceder no existe.' if wants_json_response() else 'La página a la que intenta acceder no existe.')


@bp.app_errorhandler(AppErrorBaseClass)
def handle_app_base_error(e):
    return MultiResponse(500, str(e))


@bp.app_errorhandler(ObjectNotFound)
def handle_object_not_found_error(e):
    return MultiResponse(404, str(e))


@bp.app_errorhandler(BadRequest)
def handle_bad_request_error(e):
    return MultiResponse(400, str(e))


@bp.app_errorhandler(Unauthorized)
def handle_unauthorized_error(e):
    return MultiResponse(401, str(e))


@bp.app_errorhandler(TokenExpired)
def handle_token_expired_error(e):
    return MultiResponse(401, str(e), data={'token_expired': True})
