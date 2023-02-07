class AppErrorBaseClass(Exception):
    pass


class ObjectNotFound(AppErrorBaseClass):
    pass


class BadRequest(AppErrorBaseClass):
    pass


class Unauthorized(AppErrorBaseClass):
    pass


class TokenExpired(AppErrorBaseClass):
    pass


class UserNotFound(BadRequest):
    def __init__(self, *args):
        self.message = args[0] if args else 'El usuario no existe.'

    def __str__(self):
        return self.message
