"""Excepciones de PySRI."""


class PySRIError(Exception):
    """Error base de la librería."""


class CertificateError(PySRIError):
    """El certificado .p12 no se pudo cargar o no es válido para firmar."""


class SignatureError(PySRIError):
    """Error al firmar el comprobante."""


class InvalidXMLError(PySRIError):
    """El XML de entrada es inválido o inseguro."""


class SRIConnectionError(PySRIError):
    """No se pudo comunicar con los servicios web del SRI."""


class SRIResponseError(PySRIError):
    """El SRI devolvió una respuesta inesperada o un SOAP Fault."""
