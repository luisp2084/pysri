"""Cliente de los servicios web SOAP del SRI (recepción y autorización offline)."""
import base64
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
from lxml import etree

from pysri.constants import SRI_URLS
from pysri.exceptions import InvalidXMLError, SRIConnectionError, SRIResponseError
from pysri.schemas.common import AmbienteType
from pysri.utils.access_key import is_valid_access_key
from pysri.utils.xml import local_name, parse_xml

MAX_RESPONSE_BYTES = 10 * 1024 * 1024

_RECEPTION_ENVELOPE = (
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
    'xmlns:ec="http://ec.gob.sri.ws.recepcion"><soapenv:Header/><soapenv:Body>'
    "<ec:validarComprobante><xml>{payload}</xml></ec:validarComprobante>"
    "</soapenv:Body></soapenv:Envelope>"
)
_AUTHORIZATION_ENVELOPE = (
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
    'xmlns:ec="http://ec.gob.sri.ws.autorizacion"><soapenv:Header/><soapenv:Body>'
    "<ec:autorizacionComprobante><claveAccesoComprobante>{key}</claveAccesoComprobante>"
    "</ec:autorizacionComprobante></soapenv:Body></soapenv:Envelope>"
)


@dataclass
class SRIMessage:
    identificador: Optional[str] = None
    mensaje: Optional[str] = None
    informacionAdicional: Optional[str] = None
    tipo: Optional[str] = None


@dataclass
class ReceptionResponse:
    estado: str
    clave_acceso: Optional[str] = None
    mensajes: list[SRIMessage] = field(default_factory=list)

    @property
    def received(self) -> bool:
        return self.estado == "RECIBIDA"


@dataclass
class Authorization:
    estado: str
    numero_autorizacion: Optional[str] = None
    fecha_autorizacion: Optional[str] = None
    ambiente: Optional[str] = None
    comprobante: Optional[str] = None
    mensajes: list[SRIMessage] = field(default_factory=list)

    @property
    def authorized(self) -> bool:
        return self.estado == "AUTORIZADO"


@dataclass
class AuthorizationResponse:
    clave_acceso: Optional[str]
    numero_comprobantes: int
    autorizaciones: list[Authorization] = field(default_factory=list)

    @property
    def latest(self) -> Optional[Authorization]:
        # Si hay varias, se prioriza la autorizada.
        for a in self.autorizaciones:
            if a.authorized:
                return a
        return self.autorizaciones[0] if self.autorizaciones else None


def _child_text(element: etree._Element, name: str) -> Optional[str]:
    for child in element:
        if isinstance(child.tag, str) and local_name(child) == name:
            return child.text.strip() if child.text else None
    return None


def _find_all(element: etree._Element, name: str) -> list[etree._Element]:
    return [e for e in element.iter() if isinstance(e.tag, str) and local_name(e) == name]


def _parse_messages(element: etree._Element) -> list[SRIMessage]:
    out = []
    for container in _find_all(element, "mensajes"):
        for m in container:
            if isinstance(m.tag, str) and local_name(m) == "mensaje":
                out.append(SRIMessage(
                    identificador=_child_text(m, "identificador"),
                    mensaje=_child_text(m, "mensaje"),
                    informacionAdicional=_child_text(m, "informacionAdicional"),
                    tipo=_child_text(m, "tipo"),
                ))
    return out


def _parse_soap(content: bytes) -> etree._Element:
    try:
        root = parse_xml(content, max_bytes=MAX_RESPONSE_BYTES)
    except InvalidXMLError as exc:
        raise SRIResponseError(f"Respuesta del SRI no es XML válido: {exc}") from None
    faults = _find_all(root, "Fault")
    if faults:
        reason = _child_text(faults[0], "faultstring") or "SOAP Fault"
        raise SRIResponseError(f"El SRI devolvió un error: {reason}")
    return root


def parse_reception_response(content: bytes) -> ReceptionResponse:
    root = _parse_soap(content)
    nodes = _find_all(root, "RespuestaRecepcionComprobante")
    if not nodes:
        raise SRIResponseError("Respuesta de recepción sin RespuestaRecepcionComprobante")
    node = nodes[0]
    clave = None
    comprobantes = _find_all(node, "comprobante")
    if comprobantes:
        clave = _child_text(comprobantes[0], "claveAcceso")
    return ReceptionResponse(
        estado=_child_text(node, "estado") or "DESCONOCIDO",
        clave_acceso=clave,
        mensajes=_parse_messages(node),
    )


def parse_authorization_response(content: bytes) -> AuthorizationResponse:
    root = _parse_soap(content)
    nodes = _find_all(root, "RespuestaAutorizacionComprobante")
    if not nodes:
        raise SRIResponseError("Respuesta de autorización sin RespuestaAutorizacionComprobante")
    node = nodes[0]
    try:
        count = int(_child_text(node, "numeroComprobantes") or 0)
    except ValueError:
        count = 0
    auths = []
    for a in _find_all(node, "autorizacion"):
        auths.append(Authorization(
            estado=_child_text(a, "estado") or "DESCONOCIDO",
            numero_autorizacion=_child_text(a, "numeroAutorizacion"),
            fecha_autorizacion=_child_text(a, "fechaAutorizacion"),
            ambiente=_child_text(a, "ambiente"),
            comprobante=_child_text(a, "comprobante"),
            mensajes=_parse_messages(a),
        ))
    return AuthorizationResponse(
        clave_acceso=_child_text(node, "claveAccesoConsultada"),
        numero_comprobantes=count,
        autorizaciones=auths,
    )


class SRIClient:
    """Cliente síncrono de los web services del SRI."""

    def __init__(
        self,
        ambiente: AmbienteType | str = AmbienteType.PRUEBAS,
        *,
        timeout: float = 30.0,
        verify_tls: bool = True,
        session: Optional[requests.Session] = None,
    ):
        ambiente = AmbienteType(ambiente)
        self.ambiente = ambiente
        self.urls = SRI_URLS[ambiente.value]
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session = session or requests.Session()

    def _post(self, url: str, body: str) -> bytes:
        headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": ""}
        try:
            with self.session.post(url, data=body.encode("utf-8"), headers=headers,
                                   timeout=self.timeout, verify=self.verify_tls, stream=True) as resp:
                chunks, size = [], 0
                for chunk in resp.iter_content(64 * 1024):
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise SRIResponseError("Respuesta del SRI demasiado grande")
                    chunks.append(chunk)
                content = b"".join(chunks)
                if resp.status_code >= 500 and b"Fault" not in content:
                    raise SRIConnectionError(f"El SRI respondió HTTP {resp.status_code}")
                return content
        except requests.RequestException as exc:
            raise SRIConnectionError(f"No se pudo conectar con el SRI: {exc.__class__.__name__}") from None

    def send_receipt(self, signed_xml: bytes) -> ReceptionResponse:
        """Envía el comprobante firmado al servicio de recepción."""
        payload = base64.b64encode(signed_xml).decode("ascii")
        content = self._post(self.urls["reception"], _RECEPTION_ENVELOPE.format(payload=payload))
        return parse_reception_response(content)

    def authorize(self, access_key: str) -> AuthorizationResponse:
        """Consulta la autorización de un comprobante por su clave de acceso."""
        if not is_valid_access_key(access_key):
            raise ValueError("Clave de acceso inválida")
        content = self._post(self.urls["authorization"], _AUTHORIZATION_ENVELOPE.format(key=access_key))
        return parse_authorization_response(content)

    def wait_for_authorization(self, access_key: str, attempts: int = 5, delay: float = 3.0) -> AuthorizationResponse:
        """Consulta la autorización reintentando mientras el SRI la procesa."""
        response = None
        for i in range(max(1, attempts)):
            response = self.authorize(access_key)
            latest = response.latest
            if latest is not None and latest.estado != "EN PROCESO":
                return response
            if i < attempts - 1:
                time.sleep(delay * (i + 1))
        assert response is not None
        return response
