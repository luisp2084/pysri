"""Flujo completo: validar → generar XML → firmar → recepción → autorización."""
from dataclasses import dataclass
from typing import Any, Optional, Union

from pysri.constants import ALREADY_RECEIVED_CODES
from pysri.exceptions import InvalidXMLError
from pysri.schemas.common import AmbienteType
from pysri.schemas.invoice import Invoice
from pysri.services.sri import AuthorizationResponse, ReceptionResponse, SRIClient
from pysri.signing.xades import SigningCredentials, load_p12, sign_xml
from pysri.utils.access_key import is_valid_access_key
from pysri.utils.xml import local_name, parse_xml


@dataclass
class InvoiceResult:
    access_key: str
    signed_xml: bytes
    reception: ReceptionResponse
    authorization: Optional[AuthorizationResponse] = None

    @property
    def authorized(self) -> bool:
        latest = self.authorization.latest if self.authorization else None
        return bool(latest and latest.authorized)


def build_invoice_xml(invoice: Union[dict[str, Any], Invoice, str, bytes],
                      environ: AmbienteType, validate_input: bool = True) -> tuple[bytes, str]:
    """Devuelve (xml_sin_firmar, clave_acceso)."""
    if isinstance(invoice, dict):
        invoice = Invoice.model_validate(invoice)
    if isinstance(invoice, Invoice):
        if invoice.infoTributaria.ambiente != environ:
            raise ValueError("El ambiente de la factura no coincide con el ambiente solicitado")
        return invoice.to_xml(), invoice.access_key
    if isinstance(invoice, (str, bytes)):
        root = parse_xml(invoice)
        key = None
        ambiente = None
        for el in root.iter():
            if isinstance(el.tag, str):
                if local_name(el) == "claveAcceso":
                    key = (el.text or "").strip()
                elif local_name(el) == "ambiente" and ambiente is None:
                    ambiente = (el.text or "").strip()
        if validate_input:
            if root.get("id") != "comprobante":
                raise InvalidXMLError('El nodo raíz debe tener id="comprobante"')
            if not key or not is_valid_access_key(key):
                raise InvalidXMLError("El XML no contiene una claveAcceso válida")
            if ambiente != environ.value:
                raise InvalidXMLError("El ambiente del XML no coincide con el ambiente solicitado")
        data = invoice.encode("utf-8") if isinstance(invoice, str) else invoice
        return data, key or ""
    raise TypeError("invoice debe ser dict, Invoice, str o bytes")


def sign_invoice(p12_file: bytes, password: Union[bytes, str],
                 invoice: Union[dict[str, Any], Invoice, str, bytes],
                 environ: AmbienteType = AmbienteType.PRUEBAS,
                 validate_input: bool = True,
                 credentials: Optional[SigningCredentials] = None) -> tuple[bytes, str]:
    """Firma la factura y devuelve (xml_firmado, clave_acceso)."""
    xml, key = build_invoice_xml(invoice, AmbienteType(environ), validate_input)
    creds = credentials or load_p12(p12_file, password)
    return sign_xml(p12_file, password, xml, credentials=creds), key


def sign_invoice_and_authorize(
    p12_file: bytes,
    password: Union[bytes, str],
    invoice: Union[dict[str, Any], Invoice, str, bytes],
    environ: AmbienteType = AmbienteType.PRUEBAS,
    validate_input: bool = True,
    *,
    client: Optional[SRIClient] = None,
    attempts: int = 5,
    delay: float = 3.0,
) -> InvoiceResult:
    """Firma la factura, la envía a recepción y consulta su autorización."""
    environ = AmbienteType(environ)
    signed, key = sign_invoice(p12_file, password, invoice, environ, validate_input)
    client = client or SRIClient(environ)
    reception = client.send_receipt(signed)
    result = InvoiceResult(access_key=key, signed_xml=signed, reception=reception)
    already = any(m.identificador in ALREADY_RECEIVED_CODES for m in reception.mensajes)
    if (reception.received or already) and key:
        result.authorization = client.wait_for_authorization(key, attempts=attempts, delay=delay)
    return result
