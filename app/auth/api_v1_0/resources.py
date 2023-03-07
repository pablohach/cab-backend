from flask import request, Blueprint, current_app
from flask_restful import Api, Resource

from app.common.enums import ROLES
from .schemas import RoleSchema, UserSchema, PermissionSchema, UserChangePasswordSchema, UserResetPasswordSchema
from ..models import Role, User, Permission
from app.common.error_handling import AppErrorBaseClass, Unauthorized, TokenExpired, BadRequest, UserNotFound, ObjectNotFound
from app.common.response import HttpStatusCodes, JsonResponse, getPaginationArgs, getPaginationArgsFromQuerystring
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.auth.decorators import jwt_role_required, jwt_permission_required
#from app.auxiliares.models import SystemConfig
#from app.auxiliares.api_v1_0.schemas import SystemConfigSchema


import logging
logger = logging.getLogger(__name__)

users_v1_0_bp = Blueprint('users_v1_0_bp', __name__)
api = Api(users_v1_0_bp)


def getAuthPayload(user, include_token=True, include_config=True):
    """
        Retorna objeto con token y user
    """
    payload = {
        'user': {'id_usuario': user.id_usuario,
                 'login': user.login,
                 'nombre': user.nombre,
                 'email': user.email,
                 'roles': user.get_name_roles(),
                 'roles_code': user.get_code_roles(),
                 'permissions_code': user.get_code_permissions(),
                 }
    }

    if include_token:
        import datetime
        from flask_jwt_extended import create_access_token

        expires = datetime.timedelta(
            hours=current_app.config['TOKEN_EXPIRATION_HOURS'] or 12)

        # Guardo los roles en el token
        user_roles = ','.join(user.get_str_code_roles())
        user_permissions = ','.join(user.get_code_permissions())
        access_token = create_access_token(fresh=True,
                                           identity=str(user.id_usuario), additional_claims={'user_roles': user_roles, 'user_permissions': user_permissions}, expires_delta=expires)
        payload['token'] = access_token

    if include_config:
    #     payload['config'] = SystemConfigSchema().dump( SystemConfig.query.all(), many=True)
        pass

    return payload


class AuthenticateApiResource(Resource):
    @jwt_required()
    def get(self):
        """
            Retorna los datos del user del token enviado
        """
        user_id = get_jwt_identity()
        user = User.get_by_id(user_id)
        if user is None:
            raise UserNotFound()
        if not user.is_active():
            raise Unauthorized('Usuario inactivo.')

        payload = getAuthPayload(user, True)
        return JsonResponse(HttpStatusCodes.OK, data=payload)


class LoginApiResource(Resource):
    def post(self):
        req = request.get_json() or {}
        if not 'username' in req or not 'password' in req:
            raise BadRequest('Faltan datos de autenticación.')
        username = req.get('username')
        # Si trae un @, asumo mail
        if '@' in username:
            user = User.get_by_email(username)
        else:
            user = User.get_by_username(username)
        if user is None:
            raise UserNotFound()
        if not user.is_active():
            raise Unauthorized('Usuario inactivo.')
         
        if not user.check_password(req.get('password')):
            raise Unauthorized('Clave de acceso inválida.')
        
        
        payload = getAuthPayload(
            user=user, include_token=req.get('include_token', '1') == '1')
        logger.debug(payload)
        return JsonResponse(HttpStatusCodes.OK, data=payload)


def sendMailResetPassword(user, is_new_user=False):
    import datetime
    from app.common.mail import send_email
    from flask_jwt_extended import create_access_token
    from flask import current_app, render_template

    # esta es para usar pantalla del backend
    #url = request.host_url + 'auth/reset/'

    # esta es para usar pantalla del frontend
    # sin port
    #url = request.host_url + 'auth/reset-pass/'
    # con port
    url = request.host + 'auth/reset-pass/'
    

    subject = '{} - {}'.format(current_app.config['SYSTEM_NAME'],
                               'Reestablecer clave de acceso' if not is_new_user else 'Alta de usuario')
    template_txt = 'email/reset_password.txt' if not is_new_user else 'email/new_user_password.txt'
    template_html = 'email/reset_password.html' if not is_new_user else 'email/new_user_password.html'

    expires = datetime.timedelta(hours=24)
    reset_token = create_access_token(
        identity=str(user.id_usuario), expires_delta=expires)

    try:
        send_email(subject=subject, recipients=[user.email, ],
                   text_body=render_template(
                       template_txt, url=url + reset_token, user=user),
                   html_body=render_template(
                       template_html, url=url + reset_token, user=user)
                   )
    except Exception as e:
        logger.error(str(e))
        return False
    return True


class ForgotPassword(Resource):
    # No requiero token de autenticacion
    def post(self):
        req = request.get_json() or {}
        if not 'email' in req:
            raise BadRequest('Falta email.')
        user = User.get_by_email(req.get('email'))
        if user is None:
            raise UserNotFound()

        message = 'Se ha enviado un correo electrónico a {} con las instrucciones para cambiar su clave de acceso.'.format(
            user.email)
        if not sendMailResetPassword(user):
            message = 'Error enviando email a {}.'.format(user.email)

        return JsonResponse(HttpStatusCodes.OK, message=message)


class ResetPassword(Resource):
    # No requiero token de autenticacion
    def post(self):
        from app.common.mail import send_email
        from flask import current_app
        from flask_jwt_extended import decode_token
        from jwt.exceptions import ExpiredSignatureError, DecodeError, InvalidTokenError
        try:

            args = request.get_json() or {}
            schema = UserResetPasswordSchema()
            errors = schema.validate(args)
            if errors:
                raise BadRequest(errors)

            user_id = decode_token(args.get('reset_token'))['sub']
            user = User.get_by_id(user_id)
            if user is None:
                raise UserNotFound()
            user.set_password(args.get('password'))
            user.save()
            message = 'Se ha enviado un correo electrónico a {} confirmando el cambio de clave de acceso.'.format(
                user.email)
            try:
                send_email(subject='{} - Restablecimiento de clave de acceso exitoso'.format(current_app.config['SYSTEM_NAME']),
                           recipients=[user.email, ],
                           text_body='El restablecimiento de la clave de acceso fue exitoso',
                           html_body='<p>El restablecimiento de la clave de acceso fue exitoso</p>'
                           )
            except Exception:
                message = 'Error enviando email a {}.'.format(user.email)

        except ExpiredSignatureError:
            raise TokenExpired('El token ha expirado. Realice un login.')
        except (DecodeError, InvalidTokenError):
            raise BadRequest('Token inválido')

        return JsonResponse(HttpStatusCodes.OK, message=message)


class ChangePassword(Resource):
    @jwt_required()
    def post(self, user_id):
        """ Cambia la clave de un usuario determinado """
        args = request.get_json() or {}
        schema = UserChangePasswordSchema()
        errors = schema.validate(args)
        if errors:
            raise BadRequest(errors)

        user = User.get_by_id(user_id)
        if user is None:
            raise UserNotFound()

        if not user.check_password(args.get('password')):
            raise Unauthorized('Clave de acceso inválida')

        user.set_password(args.get('new_password'))
        user.save()

        return JsonResponse(HttpStatusCodes.OK)


class RoleListResource(Resource):
    @jwt_permission_required('ROLES_VIEW')
    def get(self):
        """"
            Retorna lista de roles
            pudiéndole pasar datos de paginación, filtrado y orden
        """
        args_pag = getPaginationArgs(request)
        schema = RoleSchema()
        data = Role.get_paginated(schema, args_pag)
        result = schema.dump(data['items'], many=True)
        return JsonResponse(HttpStatusCodes.OK, data=result, pagination=data['pagination'])

    @jwt_permission_required('ROLES_ADD')
    def post(self):
        """ Alta de rol
        """
        from sqlalchemy.exc import IntegrityError

        args = request.get_json() or {}

        role_schema = RoleSchema()
        errors = role_schema.validate(args)
        if errors:
            raise BadRequest(errors)

        data = role_schema.load(args)

        # Verifico que no exista el name
        if Role.get_by_name(data['name']):
            raise BadRequest(
                "Ya existe el rol {}.".format(data['name']))

        role = Role(**data)
        try:
            role.save()
        except IntegrityError as e:
            raise AppErrorBaseClass(
                'Error de integridad ' + str(e))

        resp = role_schema.dump(role)

        return JsonResponse(HttpStatusCodes.CREATED, data=resp)


class RoleResource(Resource):
    @jwt_permission_required('ROLES_VIEW')
    def get(self, role_id):
        """ Retorna un rol determinado """
        role = Role.get_by_id(role_id)
        if role is None:
            raise ObjectNotFound()
        schema = RoleSchema()
        resp = schema.dump(role)
        return JsonResponse(HttpStatusCodes.OK, data=resp)

    @jwt_permission_required('ROLES_EDIT')
    def put(self, role_id):
        """ Modifica un rol determinado """

        from sqlalchemy.exc import IntegrityError
        # Verifico que exista el rol
        role = Role.get_by_id(role_id)
        if role is None:
            raise ObjectNotFound()

        if role.id <= current_app.config['FIXED_ROLES']:
            raise AppErrorBaseClass('No se permite modificar este rol')

        args = request.get_json() or {}

        role_schema = RoleSchema()
        errors = role_schema.validate(args)
        if errors:
            raise BadRequest(errors)

        data = role_schema.load(args)

        # Si viene el name, verifico que no exista el name para otro rol
        if 'name' in data:
            if Role.query.filter(Role.name == data['name']).filter(Role.id != role_id).all():
                raise BadRequest(
                    "Ya existe el rol  {}.".format(data['name']))

        role.set_data_fromdict(data)
        try:
            role.save()
        except IntegrityError as e:
            raise AppErrorBaseClass(
                'Error de integridad ' + str(e))

        resp = role_schema.dump(role)
        return JsonResponse(HttpStatusCodes.CREATED, data=resp)

    @jwt_permission_required('ROLES_DELETE')
    def delete(self, role_id):
        """ Borra un rol determinado """
        # Verifico que exista el rol
        role = Role.get_by_id(role_id)
        if role is None:
            raise ObjectNotFound()

        if role.id <= current_app.config['FIXED_ROLES']:
            raise AppErrorBaseClass('No se permite borrar este rol')

        role.delete()
        return JsonResponse(HttpStatusCodes.OK, data={'deleted': role_id})


class RolePermissionsListResource(Resource):
    @jwt_permission_required('ROLES_PERMISSIONS_VIEW')
    def get(self, role_id):
        """ Retorna los permisos del rol, ordenados
        """
        role = Role.get_by_id(role_id)
        if role is None:
            raise ObjectNotFound()
        schema = PermissionSchema()
        # retorno permisos ordenador por order
        # result = schema.dump(
        #     sorted(role.permissions, key=lambda k: k.order), many=True)
        result = schema.dump(role.get_permissions(), many=True)

        return JsonResponse(HttpStatusCodes.OK, data=result)


class RolePermissionsResource(Resource):
    @jwt_permission_required('ROLES_PERMISSIONS_EDIT')
    def put(self, role_id):
        """ Modifica los permisos de un rol determinado.
            Recibe lista de permission_id.
            Pisa todos los que habia con estos.
            Para borrar todos los permisos enviar lista vacía.
        """
        # Verifico que exista el rol
        role = Role.get_by_id(role_id)
        if role is None:
            raise ObjectNotFound()

        args = request.get_json() or {}
        if not 'permissions' in args or not isinstance(args['permissions'], list):
            raise BadRequest('Se requiere lista de permisos.')

        role.permissions = []
        role.add_permissions(args['permissions'])

        role.save()
        schema = PermissionSchema()
        permissions = role.get_permissions()
        result = schema.dump(permissions, many=True)
        return JsonResponse(HttpStatusCodes.OK, data=result)


class UserListResource(Resource):
    @jwt_permission_required(['USERS_VIEW', 'USERS_LIST'])
    def get(self):
        """"
            Retorna lista de usuarios
            pudiéndole pasar datos de paginación, filtrado y orden
        """
        from datetime import date
        from sqlalchemy import and_, or_, not_

        extra_params = [('filter_roles', list), ('isActive', (bool, int))]
        args_pag = getPaginationArgs(request, extra_params)

        filter_complex = None
        bFilter_complex = False
        if 'filter_roles' in args_pag:
            filter_complex = User.roles.any(
                Role.id.in_(args_pag['filter_roles']))
            bFilter_complex = True

        if 'isActive' in args_pag:
            filter_active = and_(User.habilitado==True)

            if not args_pag['isActive']:
                filter_active = not_(filter_active)
            filter_complex = and_(
                filter_complex if bFilter_complex else True, filter_active)
            bFilter_complex = True

        if bFilter_complex:
            args_pag['filters_complex'] = filter_complex

        # logger.debug(args_pag)

        schema = UserSchema()
        data = User.get_paginated(schema, args_pag)
        result = schema.dump(data['items'], many=True)
        return JsonResponse(HttpStatusCodes.OK, data=result, pagination=data['pagination'])

    @jwt_permission_required('USERS_ADD')
    def post(self):
        """ Alta de usuario
            Si no se envia api_password, se genera una random (sólo para que no sea null)
            y se envia mail para hacer un password reset
        """
        import secrets
        from sqlalchemy.exc import IntegrityError

        args = request.get_json() or {}
        # Si no pasaron password, genero una random, ya que no puede ser null
        # y envio mail para hacer password reset
        send_mail_password_reset = 'password' not in args or not args['password']
        logger.debug(args)
        if send_mail_password_reset:
            args['password'] = secrets.token_urlsafe(13)
            # me aseguro que tenga 20 caracteres, con los simbolos necesarios
            args['password'] = args['password'][:16] + 'Ab0!'
            
        # Solo para CAB
        args['api_password'] = args['password']
            
        user_schema = UserSchema()
        errors = user_schema.validate(args)
        if errors:
            raise BadRequest(errors)

        data = user_schema.load(args)

        # Verifico que no exista el username
        if User.get_by_username(data['login']):
            raise BadRequest(
                "Ya existe el usuario {}.".format(data['login']))

        # Verifico que no exista el email
        if User.get_by_email(data['email']):
            raise BadRequest(
                "Ya existe un usuario con el email {}.".format(data['email']))

        user = User(**data)
        user.set_password(data['api_password'])
        try:
            user.save()
        except IntegrityError as e:
            raise AppErrorBaseClass(
                'Error de integridad ' + str(e))

        resp = user_schema.dump(user)

        message = None
        if send_mail_password_reset:
            message = 'Se ha enviado un correo electrónico al usuario con las instrucciones para cambiar su clave de acceso.'
            if not sendMailResetPassword(user, True):
                message = 'Error enviando email al usuario.'

        return JsonResponse(HttpStatusCodes.CREATED, data=resp, message=message)


class UserResource(Resource):
    @jwt_permission_required(['USERS_VIEW', 'USERS_LIST'])
    def get(self, user_id):
        """ Retorna un usuario determinado """
        user = User.get_by_id(user_id)
        if user is None:
            raise UserNotFound()
        user_schema = UserSchema()
        resp = user_schema.dump(user)
        return JsonResponse(HttpStatusCodes.OK, data=resp)

    @jwt_permission_required('USERS_EDIT')
    def put(self, user_id):
        """ Modifica un usuario determinado """

        from sqlalchemy.exc import IntegrityError
        # Verifico que exista el usuario
        user = User.get_by_id(user_id)
        if user is None:
            raise UserNotFound()

        args = request.get_json() or {}
        user_schema = UserSchema(
            partial=("login", "email", "nombre", "habilitado",))
        errors = user_schema.validate(args)
        if errors:
            raise BadRequest(errors)

        data = user_schema.load(args)

        # Si viene el username, verifico que no exista el username para otro usuario
        if 'login' in data:
            if User.query.filter(User.login == data['login']).filter(User.id_usuario != user_id).all():
                raise BadRequest(
                    "Ya existe el usuario  {}.".format(data['login']))

        # Si viene el email, verifico que no exista el email para otro usuario
        if 'email' in data:
            if User.query.filter(User.email == data['email']).filter(User.id_usuario != user_id).all():
                raise BadRequest(
                    "Ya existe un usuario con el email {}.".format(data['email']))

        user.set_data_fromdict(data)
        try:
            user.save()
        except IntegrityError as e:
            raise AppErrorBaseClass(
                'Error de integridad ' + str(e))

        resp = user_schema.dump(user)
        return JsonResponse(HttpStatusCodes.CREATED, data=resp)

    @jwt_permission_required('USERS_DELETE')
    def delete(self, user_id):
        """ Borra un usuario determinado """
        # Verifico que exista el usuario
        user = User.get_by_id(user_id)
        if user is None:
            raise UserNotFound()

        user.delete()
        return JsonResponse(HttpStatusCodes.OK, data={'deleted': user_id})


class UserPermissionsListResource(Resource):
    @jwt_permission_required(['USERS_PERMISSIONS', 'USERS_PERMISSIONS_VIEW'])
    def get(self, user_id):
        """ Retorna los permisos del usuario, ordenados
        """
        user = User.get_by_id(user_id)
        if user is None:
            raise UserNotFound()

        # Obtengo los permisos que vienen en el token
        has_users_permissions_view = User.has_permissions_from_token(
            'USERS_PERMISSIONS_VIEW')

        # Si no tiene el permiso USERS_PERMISSIONS_VIEW, solo puede ver sus permisos
        if (not has_users_permissions_view) and (user.id_usuario != int(get_jwt_identity())):
            raise Unauthorized(
                'Sólo tiene permitido ver sus propios permisos.')

        schema = PermissionSchema()
        permissions = user.get_permissions()
        result = schema.dump(permissions, many=True)
        return JsonResponse(HttpStatusCodes.OK, data=result)


class UserPermissionsResource(Resource):
    @jwt_permission_required('USERS_PERMISSIONS_EDIT')
    def put(self, user_id):
        """ Modifica los permisos de un usuario determinado.
            Recibe lista de permission_id.
            Pisa todos los que habia con estos.
            Para borrar todos los permisos enviar lista vacía.
        """
        # Verifico que exista el usuario
        user = User.get_by_id(user_id)
        if user is None:
            raise UserNotFound()

        args = request.get_json() or {}
        if not 'permissions' in args or not isinstance(args['permissions'], list):
            raise BadRequest('Se requiere lista de permisos.')

        user.permissions = []
        user.add_permissions(args['permissions'])
        user.save()
        schema = PermissionSchema()
        permissions = user.get_permissions()
        result = schema.dump(permissions, many=True)
        return JsonResponse(HttpStatusCodes.OK, data=result)


class PermissionListResource(Resource):
    @jwt_permission_required(['USERS_PERMISSIONS', 'USERS_PERMISSIONS_VIEW', 'ROLES_PERMISSIONS_VIEW'])
    def get(self):
        """"
            Retorna lista de permisos
            pudiéndole pasar datos de paginación, filtrado y orden
        """
        args_pag = getPaginationArgs(request)
        if not 'order' in args_pag:
            args_pag['order'] = Permission.orden
        schema = PermissionSchema()
        data = Permission.get_paginated(schema, args_pag)
        result = schema.dump(data['items'], many=True)
        return JsonResponse(HttpStatusCodes.OK, data=result, pagination=data['pagination'])


api.add_resource(AuthenticateApiResource, '/api/v1.0/auth/user',
                 endpoint='api_authenticate_resource')

api.add_resource(LoginApiResource, '/api/v1.0/auth/login',
                 endpoint='api_login_resource')
api.add_resource(ForgotPassword, '/api/v1.0/auth/forgot',
                 endpoint='user_forgot_password')
api.add_resource(ResetPassword, '/api/v1.0/auth/reset',
                 endpoint='user_reset_password')
api.add_resource(ChangePassword, '/api/v1.0/auth/change/<int:user_id>',
                 endpoint='user_change_password')


api.add_resource(RoleListResource, '/api/v1.0/roles/',
                 endpoint='role_list_resource')
api.add_resource(RoleResource, '/api/v1.0/roles/<int:role_id>',
                 endpoint='role_resource')

api.add_resource(RolePermissionsListResource, '/api/v1.0/roles/<int:role_id>/permissions/',
                 endpoint='role_permissions_list_resource')

api.add_resource(RolePermissionsResource, '/api/v1.0/roles/<int:role_id>/permissions/',
                 endpoint='role_permissions_resource')


api.add_resource(PermissionListResource, '/api/v1.0/permissions/',
                 endpoint='permission_list_resource')


api.add_resource(UserListResource, '/api/v1.0/users/',
                 endpoint='user_list_resource')
api.add_resource(UserResource, '/api/v1.0/users/<int:user_id>',
                 endpoint='user_resource')

api.add_resource(UserPermissionsListResource, '/api/v1.0/users/<int:user_id>/permissions/',
                 endpoint='user_permissions_list_resource')


api.add_resource(UserPermissionsResource, '/api/v1.0/users/<int:user_id>/permissions/',
                 endpoint='user_permissions_resource')
