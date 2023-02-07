import typing

from marshmallow import validate, fields, ValidationError, exceptions


validate.Email.default_message = "No es una dirección de mail válida."
validate.URL.default_message = "No es una URL válida."
validate.Equal.default_message = "Debe ser igual a {other}."
validate.Regexp.default_message = "La cadena no coincide con el patrón esperado."
validate.Predicate.default_message = "Ingreso inválido."
validate.NoneOf.default_message = "Ingreso inválido."
validate.OneOf.default_message = "Debe ser uno de: {choices}."
validate.ContainsOnly.default_message = "Una o más de las elecciones que tomó no estaba en: {choices}."
validate.ContainsNoneOf.default_message = "Una o más de las elecciones que tomó fue en: {values}."

fields.Field.default_error_messages["required"] = "Faltan datos para el campo obligatorio."
fields.Field.default_error_messages["null"] = "El campo no puede ser nulo."
fields.Field.default_error_messages["validator_failed"] = "Valor inválido."

fields.Email.default_error_messages["invalid"] = "No es una dirección de mail válida."

fields.Number.default_error_messages["invalid"] = "No es un número válido"
fields.Number.default_error_messages["too_large"] = "Número muy largo"

fields.Integer.default_error_messages["invalid"] = "No es un entero válido"

fields.String.default_error_messages["invalid"] = "No es un texto válido"
fields.String.default_error_messages["invalid_utf8"] = "No es un texto utf-8 válido"

fields.Boolean.default_error_messages["invalid"] = "No es un booleano válido"

fields.DateTime.default_error_messages["invalid"] = "{obj_type} inválido."
fields.DateTime.default_error_messages["invalid"] = "{awareness} {obj_type} inválido."
fields.DateTime.default_error_messages["invalid"] = '"{input}" no puede ser formateado como {obj_type}.'

fields.Date.default_error_messages["invalid"] = "Fecha inválida."
fields.Date.default_error_messages["format"] = '"{input}" no puede ser formateado como fecha.'

fields.Url.default_error_messages["invalid"] = "No es una URL válida."
fields.IP.default_error_messages["invalid"] = "No es una dirección IP válida."
fields.IPv4.default_error_messages["invalid"] = "No es una dirección IPv4 válida."
fields.IPv6.default_error_messages["invalid"] = "No es una dirección IPv6 válida."
fields.IPInterface.default_error_messages["invalid"] = "No es una interfáz IP válida."
fields.IPv4Interface.default_error_messages["invalid"] = "No es una interfáz IPv4 válida."
fields.IPv6Interface.default_error_messages["invalid"] = "No es una interfáz IPv6 válida."
fields.List.default_error_messages = {"invalid": "No es una lista válida."}

password_validator_error_messages = {'validator_failed':
                                     'La clave debe tener entre 8 y 20 caracteres, al menos un dígito, un símbolo, una mayúscula y una minúscula. No puede empezar ni terminar con un espacio.'}


not_blank = validate.Length(min=1, error='No puede estar vacío')


class Password(validate.Validator):
    default_message = "La clave debe tener entre 8 y 20 caracteres, al menos un dígito, un símbolo, una mayúscula y una minúscula. No puede empezar ni terminar con un espacio."

    def __init__(self, *, error: typing.Optional[str] = None):
        self.error = error or self.default_message  # type: str

    def _format_error(self, value: str, message: str) -> str:
        return (message or self.error).format(input=value)

    def __call__(self, value: str) -> str:
        #message = self._format_error(value)
        message = ""
        message_ini = "Debe tener "
        min_length = 8
        max_length = 20
        ret = password_check(value, min_length=min_length,
                             max_length=max_length)
        if ret['min_length_error']:
            message += "Debe tener al menos {} caracteres".format(min_length)
            message_ini = ""
        elif ret['max_length_error']:
            message += "Debe tener como máximo {} caracteres".format(
                max_length)
            message_ini = ""

        if ret['digit_error']:
            message += (", " if message else "") + "un dígito"
        if ret['uppercase_error']:
            message += (", " if message else "") + "una mayúscula"
        if ret['lowercase_error']:
            message += (", " if message else "") + "una minúscula"
        if ret['symbol_error']:
            message += (", " if message else "") + "un símbolo"

        if ret['whitespace_error']:
            message += ". " if message else "" + \
                'No puede empezar ni terminar con un espacio.'

        if not ret['password_ok']:
            message = message_ini + message
            raise ValidationError(self._format_error(value, message))

        return value


def password_check(password, min_length=8, max_length=20):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        8-20 characters length
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """
    import re

    # calculating the length
    #length_error = len(password) < min_length or len(password) > max_length
    min_length_error = len(password) < min_length
    max_length_error = len(password) > max_length

    # searching for spaces at begin or end
    whitespace_error = len(password.strip()) != len(password)

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"\W", password) is None

    # overall result
    password_ok = not (
        min_length_error or max_length_error or whitespace_error or digit_error or uppercase_error or lowercase_error or symbol_error)

    return {
        'password_ok': password_ok,
        'min_length_error': min_length_error,
        'max_length_error': max_length_error,
        'whitespace_error': whitespace_error,
        'digit_error': digit_error,
        'uppercase_error': uppercase_error,
        'lowercase_error': lowercase_error,
        'symbol_error': symbol_error,
    }


def validate_dates_from_to(data, fieldFrom='dateFrom', fieldTo='dateTo'):
    if fieldTo in data and fieldFrom in data and data[fieldFrom] and data[fieldTo] and (data[fieldTo] < data[fieldFrom]):
        raise exceptions.ValidationError(
            "{} ({}) debe ser menor o igual a {} ({}).".format(fieldFrom, data[fieldFrom], fieldTo, data[fieldTo]))
