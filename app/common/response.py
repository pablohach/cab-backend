from typing import Dict
from flask import jsonify
from werkzeug.http import HTTP_STATUS_CODES
from werkzeug.wrappers import request
import json

import logging
logger = logging.getLogger(__name__)


class HttpStatusCodes():
    OK = 200
    CREATED = 201
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404


def JsonResponse(status_code: int, message: str = None, data=None, pagination=None):

    success = status_code in [200, 201]
    payload = {
        'success': success,
        'status_code': status_code,
        'error': None if success else HTTP_STATUS_CODES.get(status_code, 'Error desconocido'),
        'message': message,
        'pagination': pagination,
        'data': data,

    }
    response = jsonify(payload)
    response.status_code = status_code
    #response.headers.add('Access-Control-Allow-Origin', '*')

    return response


def getPaginationArgs(req: request, extra_params: list = None):
    """ Retorna Dict con los parámetros de paginación pasados en la respuesta

        Parameters
        ----------
        req: request
        extra_params: list

        Returns
        -------
        Dict : {'fromDict': True|False, 'page': n, 'per_page': n, 'order':'order', 'filters': Dict,
            extra_params
        }
    """
    # A un get no se le pueden pasar datos en el body (los browsers lo impiden)
    # Postman si puede pasarlos, por eso en un get primero espero recibirlos por querystring
    # (como debo pasarlo desde un browser).
    # Si no hay nada en el querystring, veo si vienen por json
    ret = {}
    if req.is_json:
        ret = getPaginationArgsFromDict(req.get_json() or {}, extra_params)
    elif req.args:
        ret = getPaginationArgsFromQuerystring(req.args, extra_params)

    # if req.args:
    #     ret = getPaginationArgsFromQuerystring(req.args, extra_params)
    # else:
    #     ret = getPaginationArgsFromDict(req.get_json() or {}, extra_params)
    return ret


def getPaginationArgsFromDict(args: Dict, extra_params: list = None):
    ret = {'fromDict': True, 'page': int(args['page']) if args and 'page' in args else None,
           'per_page': (int(args['per_page']) if args and 'per_page' in args else 20) if args and 'page' in args else None,
           'order': args['order'] if args and 'order' in args else None,
           'filters': args['filters'] if args and 'filters' in args and isinstance(args['filters'], (list, dict)) else None,
           }

    if args and extra_params:
        for ep in extra_params:
            # verificar si ep es una tupla, si es, chequeo el tipo
            if isinstance(ep, tuple):
                if ep[0] in args and isinstance(args[ep[0]], ep[1]):
                    ret[ep[0]] = args[ep[0]]
            else:
                if ep in args:
                    ret[ep] = args[ep]

    return ret


def getPaginationArgsFromQuerystring(args: request, extra_params: list = None):

    ret = {'fromDict': False, 'page': int(args.get('page', 1)),
           'per_page': int(args.get('per_page', 20)),
           'order': json.loads(args.get('order')) if args.get('order') else None,
           'filters': json.loads(args.get('filters')) if args.get('filters') else None,
           }
    
    if args and extra_params:
        for ep in extra_params:
            # verificar si ep es una tupla, si es, chequeo el tipo
            if isinstance(ep, tuple) and args.get(ep[0], None):
                param = json.loads(args.get(ep[0]))
                if isinstance(param, ep[1]):
                    ret[ep[0]] = param
            elif args.get(ep, None):
                param = json.loads(args.get(ep, ''))
                ret[ep] = param
    return ret


def getPaginationData(pagination):
    """ Retorna Dict con datos a mostrar de la paginación

        Parameters
        ----------
        pagination: Pagination

        Returns
        -------
        Dict 
    """
    start = 0
    end = 0
    if pagination.total:
        start = (pagination.per_page * (pagination.page - 1)) + 1
        end = start + pagination.per_page - 1
        if end > pagination.total:
            end = pagination.total
    ret = {'total': pagination.total,
           'page': pagination.page, 'pages': pagination.pages,
           'per_page': pagination.per_page,
           'from': start, 'to': end,
           'next_num': pagination.next_num, 'prev_num': pagination.prev_num
           }

    return ret
