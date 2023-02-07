from flask import request, Blueprint, current_app
from flask_restful import Api, Resource
from app.common.response import HttpStatusCodes, JsonResponse
from flask_jwt_extended import jwt_required
from app.auth.decorators import jwt_role_required, jwt_permission_required
from app.common.enums import ROLES

test_bp = Blueprint('test_bp', __name__)
api = Api(test_bp)


class PublicContentResource(Resource):
    def get(self):
        """ Test.
            Página pública.
        """
        return JsonResponse(HttpStatusCodes.OK, data='ESTA ES UNA PÁGINA PÚBLICA')


class UserBoardResource(Resource):
    @jwt_required()
    def get(self):
        """ Test.
            Página del usuario.
        """
        return JsonResponse(HttpStatusCodes.OK, data='PÁGINA DEL USUARIO')


class SupervisorBoardResource(Resource):
    @jwt_role_required([ROLES.ADMIN, ROLES.SUPER])
    def get(self):
        """ Test.
            Página del supervisor.
        """
        return JsonResponse(HttpStatusCodes.OK, data='PÁGINA DEL SUPERVISOR')


class AdministratorBoardResource(Resource):
    @jwt_role_required([ROLES.ADMIN])
    def get(self):
        """ Test.
            Página del administrador.
        """
        return JsonResponse(HttpStatusCodes.OK, data='PÁGINA DEL ADMINISTRADOR')


api.add_resource(PublicContentResource, '/api/v1.0/test/all/',
                 endpoint='public_content_resource')

api.add_resource(UserBoardResource, '/api/v1.0/test/user/',
                 endpoint='user_board_resource')

api.add_resource(SupervisorBoardResource, '/api/v1.0/test/super/',
                 endpoint='super_board_resource')

api.add_resource(AdministratorBoardResource, '/api/v1.0/test/admin/',
                 endpoint='admin_board_resource')
