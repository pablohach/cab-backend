from typing import Dict
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from app.common.response import getPaginationData
from app.common.error_handling import AppErrorBaseClass

db = SQLAlchemy()

import logging
logger = logging.getLogger(__name__)


class BaseModelMixin:
    __ID__ = None # Nombre del campo ID, para uso de __GENERATOR__
    __GENERATOR__ = None # Nombre del generator
    
    
    def save(self):
        # Si se seteo __GEN_ID__ y el campo __ID__ está vacio, llamo al __GEN_ID__ 
        if (self.__GENERATOR__) and (self.__ID__) and not getattr(self, self.__ID__):
            id = db.session.execute(text("SELECT GEN_ID( "+self.__GENERATOR__+", 1 ) FROM RDB$DATABASE")).scalar()
            if id:
                logger.debug(id)
                setattr(self, self.__ID__, id)
            else:
                raise AppErrorBaseClass('Error __GENERATOR__')
        
        ok = (not self.__ID__) or (getattr(self, self.__ID__))
        if ok:    
            db.session.add(self)
            db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()



    @classmethod
    def get_all(cls):
        return cls.query.all()

    @classmethod
    def get_all_paginated(cls, page: int = 1, per_page: int = 20):
        return cls.query.paginate(page, per_page, False)

    @classmethod
    def get_by_id(cls, id):
        return cls.query.get(id)

    @classmethod
    def simple_filter(cls, **kwargs):
        return cls.query.filter_by(**kwargs).all()

    @classmethod
    def get_paginated(cls, cls_schema, args_pag, query=None):
        """ Recibe argumentos con datos de paginacion, orden y filtrado
            y retorna items obtenidos y datos de paginacion
        """
        ret = {'items': None, 'pagination': None}
        if not query:
            query = cls.query
        if 'filters' in args_pag and args_pag['filters'] and isinstance(args_pag['filters'], (list, dict)):
            from flask_filter.schemas import FilterSchema
            filter_schema = FilterSchema()

            if isinstance(args_pag['filters'], dict):
                args_pag['filters'] = [args_pag['filters']]
            filters = filter_schema.load(args_pag['filters'], many=True)

            for f in filters:
                query = f.apply(query, cls, cls_schema)

        if 'filters_complex' in args_pag:
            query = query.filter(args_pag['filters_complex'])

        if 'order' in args_pag and args_pag['order']:
            if isinstance(args_pag['order'], str):
                query = query.order_by(text(args_pag['order']))
            else:
                query = query.order_by(args_pag['order'])
        
        if 'page' in args_pag and args_pag['page']:
            pag = query.paginate(page=args_pag['page'], per_page=args_pag['per_page'], error_out=False)
            ret['items'] = pag.items
            ret['pagination'] = getPaginationData(pag)
        else:
            ret['items'] = query.all()

        return ret
