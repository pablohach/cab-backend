import os

from app import create_app, db


settings_module = os.getenv('APP_SETTINGS_MODULE')
app = create_app(settings_module)


# Al ejecutar comandos de flask shell, esta funcion es invocada y registra los items que esta retorna
# agrego estos para poder usarlos desde el shell para pruebas sin tener que importarlos manualmente
@app.shell_context_processor
def make_shell_context():
    from app.auth.models import User, Role, Permission
    
    return {'db': db, 'User': User, 'Role': Role, 'Permission': Permission}


@app.cli.command()
def deploy():
    from app.auth.models import Role, Permission
    
    Permission.insert_permissions()
    Role.insert_roles()
    