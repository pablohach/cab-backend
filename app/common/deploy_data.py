"""
    Datos que serán insertados en la DB al ejecutar el comando "flask deploy"
"""

# Lista de roles iniciales
ROLES_DEFAULT = [
    {
        "name": "Administrador",
                "permissions": []
    },
    {
        "name": "Supervisor",
                "permissions": ['ROLES', 'ROLES_VIEW', 'ROLES_ADD', 'ROLES_EDIT', 'ROLES_DELETE', 'ROLES_PERMISSIONS_VIEW', 'ROLES_PERMISSIONS_EDIT',
                                'USERS', 'USERS_VIEW', 'USERS_LIST', 'USERS_ADD', 'USERS_EDIT', 'USERS_DELETE', 'USERS_PERMISSIONS', 'USERS_PERMISSIONS_VIEW', 'USERS_PERMISSIONS_EDIT',
                                ]
    },
    {
        "name": "Usuario base",
                "permissions": ['USERS', 'USERS_LIST', 'USERS_PERMISSIONS']
    },

]

# Lista de permisos, ponerlos en orden visual, el order se genera automáticamente al insertar
PERMISSIONS_DEFAULT = [
    {
        "code": "ROLES",
        "name": "Roles de usuarios",
        "parent": None
    },
    {
        "code": "ROLES_VIEW",
        "name": "Ver roles",
        "parent": "ROLES"
    },
    {
        "code": "ROLES_ADD",
        "name": "Agregar roles",
        "parent": "ROLES"
    },
    {
        "code": "ROLES_EDIT",
        "name": "Modificar roles",
        "parent": "ROLES"
    },
    {
        "code": "ROLES_DELETE",
        "name": "Borrar roles",
        "parent": "ROLES"
    },
    {
        "code": "ROLES_PERMISSIONS_VIEW",
        "name": "Ver permisos de roles",
        "parent": "ROLES"
    },
    {
        "code": "ROLES_PERMISSIONS_EDIT",
        "name": "Modificar permisos de roles",
        "parent": "ROLES"
    },
    {
        "code": "USERS",
        "name": "Usuarios",
        "parent": None
    },
    {
        "code": "USERS_VIEW",
        "name": "Ver usuarios",
        "parent": "USERS"
    },
    {
        "code": "USERS_LIST",
        "name": "Obtener lista usuarios",
        "parent": "USERS"
    },
    {
        "code": "USERS_ADD",
        "name": "Agregar usuarios",
        "parent": "USERS"
    },
    {
        "code": "USERS_EDIT",
        "name": "Modificar usuarios",
        "parent": "USERS"
    },
    {
        "code": "USERS_DELETE",
        "name": "Borrar usuarios",
        "parent": "USERS"
    },
    {
        "code": "USERS_PERMISSIONS",
        "name": "Ver mis permisos",
        "parent": "USERS"
    },
    {
        "code": "USERS_PERMISSIONS_VIEW",
        "name": "Ver permisos de usuarios",
        "parent": "USERS"
    },
    {
        "code": "USERS_PERMISSIONS_EDIT",
        "name": "Modificar permisos de usuarios",
        "parent": "USERS"
    },




]


