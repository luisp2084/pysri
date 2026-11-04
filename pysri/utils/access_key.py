"""Clave de acceso de 49 dígitos (ficha técnica de comprobantes electrónicos)."""
import re
import secrets
from datetime import date
from typing import NamedTuple

_ACCESS_KEY_RE = re.compile(r"^\d{49}$")


class AccessKeyParts(NamedTuple):
    fecha_emision: date
    cod_doc: str
    ruc: str
    ambiente: str
    estab: str
    pto_emi: str
    secuencial: str
    codigo_numerico: str
    tipo_emision: str
    digito_verificador: str


def mod11_check_digit(digits: str) -> str:
    """Dígito verificador módulo 11 con factores 2..7 de derecha a izquierda."""
    if not digits.isdigit():
        raise ValueError("Solo se admiten dígitos")
    total = 0
    factor = 2
    for ch in reversed(digits):
        total += int(ch) * factor
        factor = 2 if factor == 7 else factor + 1
    result = 11 - (total % 11)
    if result == 11:
        return "0"
    if result == 10:
        return "1"
    return str(result)


def generate_access_key(
    fecha_emision: date,
    cod_doc: str,
    ruc: str,
    ambiente: str,
    estab: str,
    pto_emi: str,
    secuencial: str,
    codigo_numerico: str | None = None,
    tipo_emision: str = "1",
) -> str:
    if codigo_numerico is None:
        codigo_numerico = f"{secrets.randbelow(10**8):08d}"
    parts = {
        "cod_doc": (cod_doc, 2),
        "ruc": (ruc, 13),
        "ambiente": (ambiente, 1),
        "estab": (estab, 3),
        "pto_emi": (pto_emi, 3),
        "secuencial": (secuencial, 9),
        "codigo_numerico": (codigo_numerico, 8),
        "tipo_emision": (tipo_emision, 1),
    }
    for name, (value, length) in parts.items():
        if not (isinstance(value, str) and value.isdigit() and len(value) == length):
            raise ValueError(f"{name} debe tener exactamente {length} dígitos")
    base = (
        fecha_emision.strftime("%d%m%Y")
        + cod_doc + ruc + ambiente + estab + pto_emi + secuencial
        + codigo_numerico + tipo_emision
    )
    return base + mod11_check_digit(base)


def is_valid_access_key(key: str) -> bool:
    if not isinstance(key, str) or not _ACCESS_KEY_RE.match(key):
        return False
    try:
        parse_access_key(key)
    except ValueError:
        return False
    return mod11_check_digit(key[:48]) == key[48]


def parse_access_key(key: str) -> AccessKeyParts:
    if not _ACCESS_KEY_RE.match(key or ""):
        raise ValueError("La clave de acceso debe tener 49 dígitos")
    fecha = date(int(key[4:8]), int(key[2:4]), int(key[0:2]))
    return AccessKeyParts(
        fecha_emision=fecha,
        cod_doc=key[8:10],
        ruc=key[10:23],
        ambiente=key[23],
        estab=key[24:27],
        pto_emi=key[27:30],
        secuencial=key[30:39],
        codigo_numerico=key[39:47],
        tipo_emision=key[47],
        digito_verificador=key[48],
    )
