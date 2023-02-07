#from sqlalchemy.types import Integer, SmallInteger, Numeric, String
from sqlalchemy_firebird.base import INTEGER, SMALLINT, NUMERIC


DB_type_Int = INTEGER
DB_type_UnsignedInt = INTEGER

DB_type_SmallInt = SMALLINT
DB_type_UnsignedSmallInt = SMALLINT

DB_type_Money = NUMERIC(15, 2)

DB_type_Boolean = SMALLINT




DB_type_Percentage = NUMERIC(7, 4)
