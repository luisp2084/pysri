"""Validación de cédula y RUC ecuatorianos."""
import re

_PROVINCES = set(range(1, 25)) | {30}  # 30 = ecuatorianos registrados en el exterior


def is_valid_cedula(value: str) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"\d{10}", value):
        return False
    if int(value[:2]) not in _PROVINCES or int(value[2]) >= 6:
        return False
    total = 0
    for i, ch in enumerate(value[:9]):
        n = int(ch) * (2 if i % 2 == 0 else 1)
        total += n - 9 if n > 9 else n
    check = (10 - total % 10) % 10
    return check == int(value[9])


def _mod11(digits: str, weights: list[int]) -> int:
    total = sum(int(d) * w for d, w in zip(digits, weights, strict=True))
    rest = total % 11
    return 0 if rest == 0 else 11 - rest


def is_valid_ruc(value: str, strict: bool = False) -> bool:
    """Valida un RUC.

    Para sociedades (tercer dígito 6 o 9) el SRI emite desde 2022 RUCs que no
    cumplen el dígito verificador módulo 11, por eso solo se comprueba con
    ``strict=True``. Las personas naturales siempre se validan contra la cédula.
    """
    if not isinstance(value, str) or not re.fullmatch(r"\d{13}", value):
        return False
    if int(value[:2]) not in _PROVINCES:
        return False
    third = int(value[2])
    if third < 6:  # persona natural
        return is_valid_cedula(value[:10]) and value[10:] != "000"
    if third == 6:  # sector público
        if value[9:] == "0000":
            return False
        return not strict or _mod11(value[:8], [3, 2, 7, 6, 5, 4, 3, 2]) == int(value[8])
    if third == 9:  # sociedad privada / extranjeros sin cédula
        if value[10:] == "000":
            return False
        return not strict or _mod11(value[:9], [4, 3, 2, 7, 6, 5, 4, 3, 2]) == int(value[9])
    return False
