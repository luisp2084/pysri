import pytest

from pysri.utils.identification import is_valid_cedula, is_valid_ruc


@pytest.mark.parametrize("value", ["1712345675", "0923456784", "0102030400"])
def test_valid_cedulas(value):
    assert is_valid_cedula(value)


@pytest.mark.parametrize("value", ["1712345670", "2512345675", "1792345675", "abc", "17123456", ""])
def test_invalid_cedulas(value):
    assert not is_valid_cedula(value)


def test_ruc_natural_person():
    assert is_valid_ruc("1712345675001")
    assert not is_valid_ruc("1712345675000")
    assert not is_valid_ruc("1712345670001")


def test_ruc_sociedad():
    # Sociedad privada con dígito verificador correcto
    assert is_valid_ruc("1790011674001", strict=True)
    assert not is_valid_ruc("1790011674000")
    # Sector público
    assert is_valid_ruc("1760001550001", strict=True)
