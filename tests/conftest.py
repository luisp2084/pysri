import copy
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

P12_PASSWORD = "clave-segura"
ECUADOR_TZ = timezone(timedelta(hours=-5))


def make_p12(days_valid: int = 365, password: str = P12_PASSWORD, offset_days: int = -1):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EC"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PRUEBAS PYSRI"),
        x509.NameAttribute(NameOID.COMMON_NAME, "EMPRESA DE PRUEBA S.A."),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=offset_days))
        .not_valid_after(now + timedelta(days=offset_days + days_valid))
        .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True)
        .sign(key, hashes.SHA256())
    )
    data = pkcs12.serialize_key_and_certificates(
        b"firma", key, cert, None, serialization.BestAvailableEncryption(password.encode())
    )
    return data, cert


@pytest.fixture(scope="session")
def p12_and_cert():
    return make_p12()


@pytest.fixture(scope="session")
def p12(p12_and_cert):
    return p12_and_cert[0]


@pytest.fixture(scope="session")
def certificate(p12_and_cert):
    return p12_and_cert[1]


_INVOICE = {
    "infoTributaria": {
        "ambiente": "1",
        "razonSocial": "EMPRESA DE PRUEBA S.A.",
        "nombreComercial": "MI TIENDA",
        "ruc": "1712345675001",
        "estab": "001",
        "ptoEmi": "002",
        "secuencial": "15",
        "dirMatriz": "Av. Amazonas N1-23 & Colón, Quito",
    },
    "infoFactura": {
        "fechaEmision": None,
        "dirEstablecimiento": "Av. Amazonas N1-23, Quito",
        "obligadoContabilidad": "NO",
        "tipoIdentificacionComprador": "05",
        "razonSocialComprador": "JUAN PÉREZ",
        "identificacionComprador": "0923456784",
        "direccionComprador": "Guayaquil",
        "totalSinImpuestos": "25.00",
        "totalDescuento": "1.00",
        "totalConImpuestos": [
            {"codigo": "2", "codigoPorcentaje": "4", "baseImponible": "20.00", "valor": "3.00"},
            {"codigo": "2", "codigoPorcentaje": "0", "baseImponible": "5.00", "valor": "0.00"},
        ],
        "propina": "0.00",
        "importeTotal": "28.00",
        "pagos": [{"formaPago": "19", "total": "28.00", "plazo": "0", "unidadTiempo": "dias"}],
    },
    "detalles": [
        {
            "codigoPrincipal": "P001",
            "descripcion": "Producto gravado <especial>",
            "cantidad": "2",
            "precioUnitario": "10.50",
            "descuento": "1.00",
            "precioTotalSinImpuesto": "20.00",
            "impuestos": [{"codigo": "2", "codigoPorcentaje": "4", "tarifa": "15", "baseImponible": "20.00", "valor": "3.00"}],
        },
        {
            "codigoPrincipal": "P002",
            "descripcion": "Producto tarifa 0",
            "cantidad": "1",
            "precioUnitario": "5",
            "precioTotalSinImpuesto": "5.00",
            "impuestos": [{"codigo": "2", "codigoPorcentaje": "0", "tarifa": "0", "baseImponible": "5.00", "valor": "0.00"}],
        },
    ],
    "infoAdicional": [{"nombre": "Email", "valor": "cliente@example.com"}],
}


@pytest.fixture
def invoice_data():
    data = copy.deepcopy(_INVOICE)
    data["infoFactura"]["fechaEmision"] = datetime.now(ECUADOR_TZ).date().isoformat()
    return data
