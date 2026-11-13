import base64

import pytest

from pysri import AmbienteType, sign_invoice_and_authorize
from pysri.exceptions import SRIResponseError
from pysri.schemas.invoice import Invoice
from pysri.services.sri import SRIClient, parse_authorization_response, parse_reception_response
from tests.conftest import P12_PASSWORD

RECIBIDA = b"""<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
<ns2:validarComprobanteResponse xmlns:ns2="http://ec.gob.sri.ws.recepcion">
<RespuestaRecepcionComprobante><estado>RECIBIDA</estado><comprobantes/></RespuestaRecepcionComprobante>
</ns2:validarComprobanteResponse></soap:Body></soap:Envelope>"""

DEVUELTA = b"""<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
<ns2:validarComprobanteResponse xmlns:ns2="http://ec.gob.sri.ws.recepcion">
<RespuestaRecepcionComprobante><estado>DEVUELTA</estado><comprobantes><comprobante>
<claveAcceso>123</claveAcceso><mensajes><mensaje><identificador>35</identificador>
<mensaje>ARCHIVO NO CUMPLE ESTRUCTURA XML</mensaje><tipo>ERROR</tipo></mensaje></mensajes>
</comprobante></comprobantes></RespuestaRecepcionComprobante>
</ns2:validarComprobanteResponse></soap:Body></soap:Envelope>"""


def autorizado(key: str) -> bytes:
    return f"""<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
<ns2:autorizacionComprobanteResponse xmlns:ns2="http://ec.gob.sri.ws.autorizacion">
<RespuestaAutorizacionComprobante><claveAccesoConsultada>{key}</claveAccesoConsultada>
<numeroComprobantes>1</numeroComprobantes><autorizaciones><autorizacion>
<estado>AUTORIZADO</estado><numeroAutorizacion>{key}</numeroAutorizacion>
<fechaAutorizacion>2024-03-01T10:00:00-05:00</fechaAutorizacion><ambiente>PRUEBAS</ambiente>
<comprobante><![CDATA[<factura id="comprobante"/>]]></comprobante><mensajes/>
</autorizacion></autorizaciones></RespuestaAutorizacionComprobante>
</ns2:autorizacionComprobanteResponse></soap:Body></soap:Envelope>""".encode()


FAULT = b"""<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
<soap:Fault><faultcode>soap:Server</faultcode><faultstring>boom</faultstring></soap:Fault>
</soap:Body></soap:Envelope>"""


class FakeResponse:
    def __init__(self, content: bytes, status_code: int = 200):
        self.content = content
        self.status_code = status_code

    def iter_content(self, size):
        yield self.content

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, data, headers, timeout, verify, stream):
        self.calls.append((url, data, verify))
        return FakeResponse(self.responses.pop(0))


def test_parse_reception():
    assert parse_reception_response(RECIBIDA).received
    r = parse_reception_response(DEVUELTA)
    assert r.estado == "DEVUELTA"
    assert r.mensajes[0].identificador == "35"


def test_parse_authorization():
    key = "0" * 49
    r = parse_authorization_response(autorizado(key))
    assert r.numero_comprobantes == 1
    assert r.latest.authorized
    assert r.latest.comprobante == '<factura id="comprobante"/>'


def test_soap_fault():
    with pytest.raises(SRIResponseError, match="boom"):
        parse_reception_response(FAULT)


def test_full_flow(p12, invoice_data):
    key = Invoice.model_validate(invoice_data).access_key
    invoice_data["infoTributaria"]["claveAcceso"] = key
    session = FakeSession([RECIBIDA, autorizado(key)])
    client = SRIClient(AmbienteType.PRUEBAS, session=session)
    result = sign_invoice_and_authorize(p12, P12_PASSWORD, invoice_data, AmbienteType.PRUEBAS, client=client)
    assert result.authorized
    assert result.access_key == key
    url, body, verify = session.calls[0]
    assert "celcer.sri.gob.ec" in url and verify is True
    payload = body.split(b"<xml>")[1].split(b"</xml>")[0]
    assert base64.b64decode(payload) == result.signed_xml
    assert key.encode() in session.calls[1][1]


def test_environment_mismatch(p12, invoice_data):
    with pytest.raises(ValueError, match="ambiente"):
        sign_invoice_and_authorize(p12, P12_PASSWORD, invoice_data, AmbienteType.PRODUCCION,
                                   client=SRIClient(session=FakeSession([])))
