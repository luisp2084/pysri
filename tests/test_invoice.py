from datetime import date, timedelta

import pytest
from lxml import etree
from pydantic import ValidationError

from pysri.schemas.invoice import Invoice
from pysri.utils.access_key import is_valid_access_key, parse_access_key


def test_valid_invoice_generates_access_key_and_xml(invoice_data):
    inv = Invoice.model_validate(invoice_data)
    assert is_valid_access_key(inv.access_key)
    parts = parse_access_key(inv.access_key)
    assert parts.secuencial == "000000015" and parts.pto_emi == "002" and parts.ambiente == "1"

    root = etree.fromstring(inv.to_xml())
    assert root.tag == "factura" and root.get("id") == "comprobante"
    assert root.findtext("infoTributaria/claveAcceso") == inv.access_key
    assert root.findtext("infoFactura/fechaEmision") == parts.fecha_emision.strftime("%d/%m/%Y")
    assert root.findtext("detalles/detalle/cantidad") == "2.000000"
    assert root.findtext("detalles/detalle/descripcion") == "Producto gravado <especial>"
    assert root.findtext("infoFactura/importeTotal") == "28.00"
    assert root.find("infoAdicional/campoAdicional").get("nombre") == "Email"


def test_accepts_dd_mm_yyyy(invoice_data):
    d = date.fromisoformat(invoice_data["infoFactura"]["fechaEmision"])
    invoice_data["infoFactura"]["fechaEmision"] = d.strftime("%d/%m/%Y")
    assert Invoice.model_validate(invoice_data).infoFactura.fechaEmision == d


def _error(invoice_data) -> str:
    with pytest.raises(ValidationError) as exc:
        Invoice.model_validate(invoice_data)
    return str(exc.value)


def test_rejects_wrong_totals(invoice_data):
    invoice_data["infoFactura"]["importeTotal"] = "30.00"
    invoice_data["infoFactura"]["pagos"][0]["total"] = "30.00"
    assert "importeTotal" in _error(invoice_data)


def test_rejects_wrong_line_total(invoice_data):
    invoice_data["detalles"][0]["precioTotalSinImpuesto"] = "21.00"
    assert "precioTotalSinImpuesto" in _error(invoice_data)


def test_rejects_wrong_iva_rate(invoice_data):
    invoice_data["detalles"][0]["impuestos"][0]["tarifa"] = "12"
    assert "tarifa" in _error(invoice_data)


def test_rejects_payments_mismatch(invoice_data):
    invoice_data["infoFactura"]["pagos"][0]["total"] = "10.00"
    assert "pagos" in _error(invoice_data)


def test_rejects_invalid_buyer_cedula(invoice_data):
    invoice_data["infoFactura"]["identificacionComprador"] = "0923456780"
    assert "cédula" in _error(invoice_data)


def test_rejects_invalid_emitter_ruc(invoice_data):
    invoice_data["infoTributaria"]["ruc"] = "1712345670001"
    assert "RUC" in _error(invoice_data)


def test_consumidor_final_rules(invoice_data):
    invoice_data["infoFactura"]["tipoIdentificacionComprador"] = "07"
    invoice_data["infoFactura"]["identificacionComprador"] = "9999999999999"
    Invoice.model_validate(invoice_data)  # 28 USD < límite
    invoice_data["infoFactura"]["identificacionComprador"] = "1712345675"
    assert "consumidor final" in _error(invoice_data)


def test_rejects_future_date(invoice_data):
    invoice_data["infoFactura"]["fechaEmision"] = (date.today() + timedelta(days=3)).isoformat()
    assert "futura" in _error(invoice_data)


def test_rejects_extra_fields_and_control_chars(invoice_data):
    invoice_data["infoTributaria"]["hack"] = "x"
    assert "hack" in _error(invoice_data)
    del invoice_data["infoTributaria"]["hack"]
    invoice_data["detalles"][0]["descripcion"] = "malo\x00"
    assert "descripcion" in _error(invoice_data)


def test_rejects_too_many_decimals(invoice_data):
    invoice_data["infoFactura"]["totalSinImpuestos"] = "25.001"
    assert "totalSinImpuestos" in _error(invoice_data)


def test_provided_access_key_must_match(invoice_data):
    key = Invoice.model_validate(invoice_data).access_key
    invoice_data["infoTributaria"]["claveAcceso"] = key
    assert Invoice.model_validate(invoice_data).access_key == key
    invoice_data["infoTributaria"]["secuencial"] = "16"
    assert "claveAcceso" in _error(invoice_data)
