from marshmallow import Schema, fields, validates_schema, ValidationError, exceptions, EXCLUDE, INCLUDE
from marshmallow.validate import Length, Email
from app.ext import ma
from app.auth.models import User, Role, Permission
from datetime import date
from app.common.validators import Password, not_blank, validate_dates_from_to


class UserChangePasswordSchema(Schema):
    password = fields.Str(required=True)
    new_password = fields.Str(required=True, validate=[Password()])


class UserResetPasswordSchema(Schema):
    password = fields.Str(
        required=True, validate=[Password()])
    reset_token = fields.Str(required=True)


class RoleSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Role
        ordered = True
        unknown = EXCLUDE
        
    id = ma.auto_field(dump_only=True)
    name = ma.auto_field(required=True, validate=not_blank)
    #code = ma.auto_field(required=True, validate=not_blank)



class PermissionSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Permission
        ordered = True
        
    id = ma.auto_field(required=True)
    code = ma.auto_field(required=True)
    name = ma.auto_field(required=True)
    orden = ma.auto_field(required=False)
    parent = ma.auto_field(required=False)
    kind =  fields.String(dump_only=True, required=False)  


# con ma.SQLAlchemyAutoSchema se generan todos los campos automaticamente
# en este caso no me sirve, ya que hay cosas que no las quiero, como password


class UserSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User
        # para que mantenga el orden de cómo fueron definidos (y no ordene alfabéticamente)
        # In production it’s recommended to let jsonify sort the keys and not set ordered=True
        # in your SQLAlchemySchema in order to minimize generation time and maximize cacheability
        # of the results.
        ordered = True
        unknown = EXCLUDE

    # Algunos campos que son NOT NULL igualmente los pongo required=False para que en el update
    # se puedan mandar sólo los campos que se desean modificar
    # y los que no vienen no se tocan
    id_usuario = ma.auto_field(dump_only=True)
    login = ma.auto_field(required=True, validate=not_blank)
    nombre = ma.auto_field(required=True, validate=not_blank)
    email = ma.auto_field( validate=[Email(), Length(max=100)])
    habilitado = ma.auto_field(required=True)
    api_password = ma.auto_field(missing=None, required=False,
                             load_only=True, validate=[Password()])

    roles = fields.Nested(RoleSchema, many=True, dump_only=True)

    # role_codes la uso para pasarle los roles que quiero agregar
    role_codes = fields.List(fields.Integer(strict=False), required=False, load_only=True)

    #isActive = fields.Method("is_active", dump_only=True)

    @validates_schema
    def validate_username(self, data, **kwargs):
        if 'login' in data and '@' in data['login']:
            raise exceptions.ValidationError(
                'Nombre de usuario no puede contener "@"')

    @validates_schema
    def validate_dates(self, data, **kwargs):
        validate_dates_from_to(data)

    @validates_schema
    def validate_roles(self, data, **kwargs):
        if 'role_codes' in data:
            if not Role.check_valid_role_codes(data['role_codes']):
                raise exceptions.ValidationError('Roles inválidos')

    def format_name(self, user):
        return user.nombre

    def is_active(self, user):
        return user.habilitado
