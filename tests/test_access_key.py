from datetime import date

import pytest

from pysri.utils.access_key import generate_access_key, is_valid_access_key, mod11_check_digit, parse_access_key


def test_mod11_known_value():
    # Ejemplo de la ficha técnica del SRI: base 41261533 → dígito 6
    assert mod11_check_digit("41261533") == "6"


def test_generate_and_parse_roundtrip():
    key = generate_access_key(date(2024, 3, 1), "01", "1712345675001", "1", "001", "002", "000000015", "12345678")
    assert len(key) == 49
    assert is_valid_access_key(key)
    parts = parse_access_key(key)
    assert parts.fecha_emision == date(2024, 3, 1)
    assert parts.ruc == "1712345675001"
    assert parts.secuencial == "000000015"
    assert parts.codigo_numerico == "12345678"


def test_tampered_key_is_invalid():
    key = generate_access_key(date(2024, 3, 1), "01", "1712345675001", "1", "001", "002", "000000015", "12345678")
    tampered = key[:-1] + str((int(key[-1]) + 1) % 10)
    assert not is_valid_access_key(tampered)
    assert not is_valid_access_key("123")
    assert not is_valid_access_key("a" * 49)


def test_invalid_parts_rejected():
    with pytest.raises(ValueError):
        generate_access_key(date(2024, 3, 1), "01", "123", "1", "001", "002", "000000015")
