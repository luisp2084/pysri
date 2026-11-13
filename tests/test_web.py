import json

import pytest
from fastapi.testclient import TestClient

from pysri.schemas.invoice import Invoice
from pysri.services.sri import SRIClient
from tests.conftest import P12_PASSWORD
from tests.test_sri_client import RECIBIDA, FakeSession, autorizado
from web.config import Settings
from web.main import create_app
from web.security import hash_api_key

API_KEY = "test-key-123"


def make_settings(**overrides) -> Settings:
    base = dict(env="production", api_key_hashes=frozenset({hash_api_key(API_KEY)}),
                allowed_hosts=["testserver"], sri_auth_delay=0, sri_auth_attempts=1)
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def sessions():
    return []


@pytest.fixture
def client(sessions):
    def factory(ambiente):
        session = sessions.pop(0) if sessions else FakeSession([])
        return SRIClient(ambiente, session=session)
    return TestClient(create_app(make_settings(), sri_client_factory=factory))


H = {"X-API-Key": API_KEY}


def files(p12, invoice_data, password=P12_PASSWORD, name="firma.p12"):
    return (
        {"certificate": (name, p12, "application/x-pkcs12")},
        {"password": password, "invoice": json.dumps(invoice_data)},
    )


def test_health_and_security_headers(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "strict-transport-security" in r.headers
    assert r.headers["cache-control"] == "no-store"


def test_index_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "PySRI" in r.text


def test_docs_disabled_in_production(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_requires_api_key(client, invoice_data):
    assert client.post("/api/v1/invoices/validate", json=invoice_data).status_code == 401
    assert client.post("/api/v1/invoices/validate", json=invoice_data,
                       headers={"X-API-Key": "mala"}).status_code == 401


def test_untrusted_host_rejected(client):
    assert client.get("/api/v1/health", headers={"Host": "evil.com"}).status_code == 400


def test_validate(client, invoice_data):
    r = client.post("/api/v1/invoices/validate", json=invoice_data, headers=H)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["accessKey"]) == 49 and 'id="comprobante"' in body["xml"]


def test_validate_errors_are_clean(client, invoice_data):
    invoice_data["infoFactura"]["importeTotal"] = "99.00"
    r = client.post("/api/v1/invoices/validate", json=invoice_data, headers=H)
    assert r.status_code == 422
    body = r.json()
    assert body["detail"] == "Datos inválidos"
    assert "importeTotal" in body["errores"][0]["error"]
    assert "input" not in json.dumps(body)


def test_sign(client, p12, invoice_data):
    f, d = files(p12, invoice_data)
    r = client.post("/api/v1/invoices/sign", files=f, data=d, headers=H)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "ds:Signature" in body["signedXml"]
    assert "EMPRESA DE PRUEBA" in body["certificateSubject"]


def test_sign_wrong_password_does_not_leak(client, p12, invoice_data):
    f, d = files(p12, invoice_data, password="secreto-incorrecto")
    r = client.post("/api/v1/invoices/sign", files=f, data=d, headers=H)
    assert r.status_code == 400
    assert "secreto-incorrecto" not in r.text


def test_sign_rejects_bad_extension_and_big_file(client, p12, invoice_data):
    f, d = files(p12, invoice_data, name="firma.exe")
    assert client.post("/api/v1/invoices/sign", files=f, data=d, headers=H).status_code == 400
    f, d = files(b"x" * (200 * 1024), invoice_data)
    assert client.post("/api/v1/invoices/sign", files=f, data=d, headers=H).status_code == 413


def test_sign_invalid_invoice_json(client, p12, invoice_data):
    f, d = files(p12, invoice_data)
    d["invoice"] = "{no json"
    r = client.post("/api/v1/invoices/sign", files=f, data=d, headers=H)
    assert r.status_code == 422


def test_body_size_limit(client):
    r = client.post("/api/v1/invoices/validate", content=b"x" * (2 * 1024 * 1024),
                    headers={**H, "Content-Type": "application/json"})
    assert r.status_code == 413


def test_production_blocked_by_default(client, invoice_data):
    invoice_data["infoTributaria"]["ambiente"] = "2"
    r = client.post("/api/v1/invoices/validate", json=invoice_data, headers=H)
    assert r.status_code == 403


def test_send_full_flow(client, sessions, p12, invoice_data):
    key = Invoice.model_validate(invoice_data).access_key
    invoice_data["infoTributaria"]["claveAcceso"] = key
    sessions.append(FakeSession([RECIBIDA, autorizado(key)]))
    f, d = files(p12, invoice_data)
    r = client.post("/api/v1/invoices/send", files=f, data=d, headers=H)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["authorized"] is True
    assert body["reception"]["estado"] == "RECIBIDA"
    assert body["authorization"]["numeroAutorizacion"] == key


def test_authorization_lookup(client, sessions, invoice_data):
    key = Invoice.model_validate(invoice_data).access_key
    sessions.append(FakeSession([autorizado(key)]))
    r = client.get(f"/api/v1/invoices/{key}/authorization", headers=H)
    assert r.status_code == 200 and r.json()["estado"] == "AUTORIZADO"
    bad = key[:-1] + str((int(key[-1]) + 1) % 10)
    assert client.get(f"/api/v1/invoices/{bad}/authorization", headers=H).status_code == 422
    assert client.get("/api/v1/invoices/123/authorization", headers=H).status_code == 422


def test_identification_tool(client):
    r = client.post("/api/v1/tools/identification", json={"tipo": "05", "numero": "1712345675"}, headers=H)
    assert r.json() == {"valid": True}
    r = client.post("/api/v1/tools/identification", json={"tipo": "04", "numero": "1712345675000"}, headers=H)
    assert r.json() == {"valid": False}


def test_rate_limit(p12, invoice_data):
    app = create_app(make_settings(sensitive_rate_limit_per_minute=2))
    c = TestClient(app)
    f, d = files(p12, invoice_data)
    codes = [c.post("/api/v1/invoices/sign", files=f, data=d, headers=H).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_settings_validation():
    with pytest.raises(RuntimeError, match="API_KEY"):
        Settings(env="production").validate()
    with pytest.raises(RuntimeError):
        Settings(env="production", api_key_hashes=frozenset({"abc"})).validate()
    # auth_disabled solo se respeta en desarrollo
    assert Settings(env="production", auth_disabled=True).auth_enabled
    assert not Settings(env="development", auth_disabled=True).auth_enabled
