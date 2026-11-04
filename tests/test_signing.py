import pytest
from cryptography.hazmat.primitives import serialization
from lxml import etree

from pysri import sign_xml
from pysri.exceptions import CertificateError, InvalidXMLError
from pysri.schemas.invoice import Invoice
from pysri.signing.xades import DS_NS, ETSI_NS, load_p12
from tests.conftest import P12_PASSWORD, make_p12

xmlsec = pytest.importorskip("xmlsec")


def verify_with_xmlsec(signed: bytes, cert) -> None:
    """Verificación independiente con libxmlsec1 (digests de las 3 referencias + firma)."""
    root = etree.fromstring(signed)
    xmlsec.tree.add_ids(root, ["Id", "id"])
    node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignature)
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_memory(cert.public_bytes(serialization.Encoding.PEM),
                                     xmlsec.constants.KeyDataFormatCertPem)
    ctx.verify(node)


def test_sign_invoice_xades_bes(p12, certificate, invoice_data):
    xml = Invoice.model_validate(invoice_data).to_xml()
    signed = sign_xml(p12, P12_PASSWORD, xml)
    assert signed.startswith(b'<?xml version="1.0" encoding="UTF-8"?>')
    verify_with_xmlsec(signed, certificate)

    root = etree.fromstring(signed)
    sig = root.find(f"{{{DS_NS}}}Signature")
    assert sig is not None and sig is root[-1]
    algs = [e.get("Algorithm") for e in sig.iter(f"{{{DS_NS}}}SignatureMethod")]
    assert algs == ["http://www.w3.org/2000/09/xmldsig#rsa-sha1"]
    refs = sig.findall(f"{{{DS_NS}}}SignedInfo/{{{DS_NS}}}Reference")
    assert [r.get("URI")[:1] for r in refs] == ["#", "#", "#"]
    assert refs[2].get("URI") == "#comprobante"
    assert root.find(f".//{{{ETSI_NS}}}SigningTime").text.endswith("-05:00")


def test_tampering_breaks_signature(p12, certificate, invoice_data):
    signed = sign_xml(p12, P12_PASSWORD, Invoice.model_validate(invoice_data).to_xml())
    tampered = signed.replace(b"<importeTotal>28.00</importeTotal>", b"<importeTotal>1.00</importeTotal>")
    with pytest.raises(xmlsec.Error):
        verify_with_xmlsec(tampered, certificate)


def test_wrong_password(p12):
    with pytest.raises(CertificateError, match="contraseña"):
        load_p12(p12, "incorrecta")


def test_expired_certificate():
    data, _ = make_p12(days_valid=10, offset_days=-20)
    with pytest.raises(CertificateError, match="caducado"):
        load_p12(data, P12_PASSWORD)


def test_garbage_certificate():
    with pytest.raises(CertificateError):
        load_p12(b"no es un p12", "x")


def test_rejects_xxe(p12):
    xxe = (b'<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
           b'<factura id="comprobante">&x;</factura>')
    with pytest.raises(InvalidXMLError):
        sign_xml(p12, P12_PASSWORD, xxe)


def test_requires_comprobante_id(p12):
    with pytest.raises(InvalidXMLError):
        sign_xml(p12, P12_PASSWORD, b"<factura/>")


def test_rejects_double_signing(p12, invoice_data):
    signed = sign_xml(p12, P12_PASSWORD, Invoice.model_validate(invoice_data).to_xml())
    with pytest.raises(InvalidXMLError, match="firmado"):
        sign_xml(p12, P12_PASSWORD, signed)
