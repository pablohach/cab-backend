from app.db import db, BaseModelMixin
import app.dbDataTypes as dt
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from app.common.deploy_data import ROLES_DEFAULT, PERMISSIONS_DEFAULT
from enum import Enum
from app.common.enums import ROLES
from flask_jwt_extended import get_jwt
from sqlalchemy import text
from app.common.error_handling import AppErrorBaseClass

import logging
logger = logging.getLogger(__name__)

user_roles = db.Table('user_roles',
                      db.Column('user_id', dt.DB_type_UnsignedInt,
                                db.ForeignKey('usuario.id_usuario', ondelete='CASCADE'), primary_key=True),
                      db.Column('role_id', dt.DB_type_UnsignedSmallInt,
                                db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True)
                      )


class RolePermissions(db.Model, BaseModelMixin):
    __tablename__ = 'role_permissions'

    permission_id = db.Column(dt.DB_type_UnsignedInt, db.ForeignKey(
        'permissions.id', ondelete='CASCADE'), primary_key=True, index=True)
    role_id = db.Column(dt.DB_type_UnsignedSmallInt,
                        db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True, index=True)

    @staticmethod
    def delete_by_role(role_id):
        RolePermissions.query.filter_by(role_id=role_id).delete()
        db.session.commit()


class UserPermissions(db.Model, BaseModelMixin):
    __tablename__ = 'user_permissions'
    user_id = db.Column(dt.DB_type_UnsignedInt,
                        db.ForeignKey('usuario.id_usuario', ondelete='CASCADE'), primary_key=True, index=True)
    permission_id = db.Column(dt.DB_type_UnsignedInt,
                              db.ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True, index=True)

    @staticmethod
    def delete_by_user(user_id):
        UserPermissions.query.filter_by(user_id=user_id).delete()
        db.session.commit()


class Role(db.Model, BaseModelMixin):
    __tablename__ = 'roles'
    __ID__ = 'id'
    __GENERATOR__ = 'gen_roles_id'
    

    id = db.Column(dt.DB_type_UnsignedSmallInt, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    permissions = db.relationship('Permission', secondary='role_permissions', lazy=True,
                                  backref=db.backref('roles', lazy=True))

    def __repr__(self):
        return f'<Role {self.id} - {self.name}>'

    @staticmethod
    def get_by_id(id):
        return Role.query.filter_by(id=id).first()

    @staticmethod
    def get_by_name(name):
        return Role.query.filter_by(name=name).first()

    @staticmethod
    def check_valid_role_codes(roles):
        ok = isinstance(roles, list)
        if ok:
            for r in roles:
                ok = isinstance(r, (int, str)) and (
                    Role.get_by_id(int(r)) != None)
                if not ok:
                    break
        return ok

    def get_permissions(self):
        """ Retorna los permisos del rol, ordenados
        """
        # Ordenar salida por orden
        return sorted(self.permissions, key=lambda k: k.orden)

    def get_code_permissions(self):
        """ Retorna los codigo permisos del rol
        """
        return [p.code for p in self.get_permissions()]

    def set_data_fromdict(self, data_dict):
        if 'name' in data_dict:
            self.name = data_dict['name']

    def add_permissions(self, permissions):
        if permissions and isinstance(permissions, (list, str, int)):
            if isinstance(permissions, (str, int)):
                permissions = [permissions]
            for p in permissions:
                if isinstance(p, Permission):
                    self.permissions.append(p)
                else:
                    if isinstance(p, str):
                        permission = Permission.get_by_code(p)
                    if isinstance(p, int):
                        permission = Permission.get_by_id(p)
                    if permission:
                        self.permissions.append(permission)

    @staticmethod
    def insert_roles():
        """ Para insertar roles. 
            Si agrego alguno ejecutar esta función. 
        """

        for r in ROLES_DEFAULT:
            # Si no existe lo agrego
            role = Role.get_by_name(r['name'])
            if role is None:
                logger.debug('rol =>' + r['name'])
                role = Role(name=r['name'])
                role.save()

            # Borro todos los permisos del rol, e inserto los definidos (vienen por code)
            # Esto ya no, sino pierdo los que van tocando ellos
            # role.permissions = []
            # role.add_permissions(r['permissions'])
            # role.save()


class Permission(db.Model, BaseModelMixin):
    __tablename__ = 'permissions'
    __ID__ = 'id'
    __GENERATOR__ = 'gen_permissions_id'
    

    id = db.Column(dt.DB_type_UnsignedInt, primary_key=True)
    code = db.Column(db.String(50), nullable=False, unique=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    orden = db.Column(dt.DB_type_UnsignedInt, nullable=True)
    # parent hace referencia a code del padre, puede no tenerlo, es para armar tree
    parent = db.Column(db.String(50), nullable=True)

    def __repr__(self):
        return f'<Permission {self.id} - {self.code} - {self.name}>'


    @staticmethod
    def get_by_code(code):
        return Permission.query.filter_by(code=code).first()

    @staticmethod
    def get_by_name(name):
        return Permission.query.filter_by(name=name).first()

    @staticmethod
    def insert_permissions():
        """ Para insertar permisos. 
            Si modifico alguno ejecutar esta función. 
            El orden lo asigno acá, automáticamente
        """
        permissions_ids = []
        orden = 0
        for p in PERMISSIONS_DEFAULT:
            orden += 1
            # Si no existe lo agrego
            permission = Permission.get_by_code(p['code'])
            if permission is None:
                logger.debug('permiso =>' + p['code'])
                permission = Permission(**p)
            else:
                # Lo modifico
                permission.name = p['name']
                permission.parent = p['parent']
            permission.orden = orden
            permission.save()
            permissions_ids.append(permission.id)

        # Borro todos los que no estaban en la lista
        Permission.query.filter(~Permission.id.in_(permissions_ids)).delete()

    @staticmethod
    def get_all_sorted():
        """
            Retorno todos ordenados para armar tree
        """
        return Permission.query.order_by(Permission.orden).all()


class User(db.Model, BaseModelMixin):
    __tablename__ = 'usuario'
    __ID__ = 'id_usuario'
    __GENERATOR__ = 'gen_usuario_id'
    

    id_usuario = db.Column(dt.DB_type_UnsignedInt, primary_key=True)
    login = db.Column(db.String(30), nullable=False, unique=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    # password es palabra reservada en FIREBIRD, tuve que cambiarla
    api_password = db.Column(db.String(200), nullable=False)
    habilitado = db.Column(dt.DB_type_Boolean, default=True, nullable=False)


    roles = db.relationship('Role', secondary=user_roles, lazy=True,
                            backref=db.backref('users', lazy=True))
    permissions = db.relationship('Permission', secondary='user_permissions', lazy=True,
                                  backref=db.backref('users', lazy=True))

    def __init__(self, login: str, nombre: str, email: str,
                 role_codes=None, habilitado: int = 1, api_password: str = None) -> None:
        self.id_usuario = None
        self.habilitado = 1 if  habilitado==1 else 0
        self.login = login
        self.nombre = nombre
        self.email = email
        if api_password:
            self.set_password(api_password)

        self.add_roles(role_codes)

    def set_data_fromdict(self, data_dict):
        if 'login' in data_dict:
            self.login = data_dict['login']
        if 'nombre' in data_dict:
            self.nombre = data_dict['nombre']
        if 'email' in data_dict:
            self.email = data_dict['email']
        if 'habilitado' in data_dict:
            self.habilitado = 1 if  data_dict['habilitado'] else 0
        if 'role_codes' in data_dict:
            self.roles = []
            self.add_roles(data_dict['role_codes'])

    def __repr__(self):
        return f'<User {self.id_usuario} {self.login} {self.nombre} {self.email}>'

    def __str__(self):
        return f'{self.nombre}'

    @staticmethod
    def get_by_username(username):
        return User.query.filter_by(login=username).first()

    @staticmethod
    def get_by_email(email):
        return User.query.filter_by(email=email).first()

    def set_password(self, password):
        self.api_password = generate_password_hash(password)

    def check_password(self, password):
        # Si no tiene clave definida, retorno False
        if not self.api_password:
            return False
        return check_password_hash(self.api_password, password)

    def is_active(self):
        return self.habilitado

    def get_code_roles(self):
        return [r.id for r in self.roles]

    def get_str_code_roles(self):
        return [str(r.id) for r in self.roles]

    def get_name_roles(self):
        return [r.name for r in self.roles]

    def add_roles(self, roles):
        if roles and isinstance(roles, (list, str)):
            if isinstance(roles, str):
                roles = [roles]
            for r in roles:
                if isinstance(r, Role):
                    self.roles.append(r)
                elif isinstance(r, (str, int)):
                    role = Role.get_by_id(r)
                    if role:
                        self.roles.append(role)

    @staticmethod
    def _has_roles(user_roles, role):
        if role is None:
            return False
        if isinstance(role, list):
            roles = role
        elif isinstance(role, tuple):
            roles = list(role)
        else:
            roles = [role]

        if user_roles is None:
            user_roles = []
        elif isinstance(user_roles, tuple):
            user_roles = list(user_roles)
        elif not isinstance(user_roles, list):
            user_roles = [user_roles]

        has = False
        for r in roles:
            if(isinstance(r, Enum)):
                r = r.value
            elif isinstance(r, int):
                r = str(r)
            if r in user_roles:
                has = True
                break
        return has

    def has_roles(self, role):
        #user_roles = self.get_code_roles()
        user_roles = self.get_str_code_roles()
        return self._has_roles(user_roles, role)

    def get_permissions(self):
        """ Retorna los permisos del los roles + los permisos del usuario
        """
        permissions = []
        permissions_codes = []

        for rol in self.roles:
            for p in rol.permissions:
                if not p.code in permissions_codes:
                    permissions_codes.append(p.code)
                    p.kind = 'R'
                    permissions.append(p)

        for p in self.permissions:
            if not p.code in permissions_codes:
                permissions_codes.append(p.code)
                p.kind = 'U'
                permissions.append(p)

        # Ordenar salida por orden
        return sorted(permissions, key=lambda k: k.orden)

    def get_code_permissions(self):
        """ Retorna los codigo permisos del los roles + los permisos del usuario
        """
        return [p.code for p in self.get_permissions()]

    def add_permissions(self, permissions):
        if permissions and isinstance(permissions, (list, str, int)):
            if isinstance(permissions, (str, int)):
                permissions = [permissions]
            for p in permissions:
                if isinstance(p, Permission):
                    self.permissions.append(p)
                else:
                    if isinstance(p, str):
                        permission = Permission.get_by_code(p)
                    elif isinstance(p, int):
                        permission = Permission.get_by_id(p)
                    if permission:
                        self.permissions.append(permission)

    @staticmethod
    def _has_permissions(user_permissions, permission):
        if permission is None:
            return False
        if isinstance(permission, list):
            permissions = permission
        elif isinstance(permission, tuple):
            permissions = list(permission)
        else:
            permissions = [permission]

        if user_permissions is None:
            user_permissions = []
        elif isinstance(user_permissions, tuple):
            user_permissions = list(user_permissions)
        elif not isinstance(user_permissions, list):
            user_permissions = [user_permissions]

        # Paso user_permissions y permissions a lower case
        for i in range(len(user_permissions)):
            user_permissions[i] = user_permissions[i].lower()
        for i in range(len(permissions)):
            permissions[i] = permissions[i].lower()

        has = False
        for p in permissions:
            if p in user_permissions:
                has = True
                break
        return has

    def has_permissions(self, permission):
        if self.has_roles(ROLES.ADMIN):
            return True
        user_permissions = self.get_code_permissions()
        return self._has_permissions(user_permissions, permission)

    @staticmethod
    def has_permissions_from_token(permission):
        claims = get_jwt()
        # Si es administrador no vienen permisos en token
        user_roles = claims['user_roles'].split(
            ',') if 'user_roles' in claims else None
        if User._has_roles(user_roles, ROLES.ADMIN):
            return True

        user_permissions = claims['user_permissions'].split(
            ',') if 'user_permissions' in claims else None
        return User._has_permissions(user_permissions, permission)
