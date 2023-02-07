from functools import wraps
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from .models import User
from app.errors.handlers import Unauthorized
from app.common.enums import ROLES


def jwt_role_required(role=None):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            user_roles = claims['user_roles'].split(
                ',') if 'user_roles' in claims else None
            if not User._has_roles(user_roles, role):
                raise Unauthorized(
                    'No tiene los permisos necesarios para realizar está operación.')

            return fn(*args, **kwargs)
        return decorator
    return wrapper


def jwt_permission_required(permission=None):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            user_roles = claims['user_roles'].split(
                ',') if 'user_roles' in claims else None
            user_permissions = claims['user_permissions'].split(
                ',') if 'user_permissions' in claims else None

            # Si tiene el rol Administrador tiene todos los permisos
            if not User._has_roles(user_roles, ROLES.ADMIN):
                if not User._has_permissions(user_permissions, permission):
                    raise Unauthorized(
                        'No tiene los permisos necesarios para realizar está operación.')

            return fn(*args, **kwargs)
        return decorator
    return wrapper
