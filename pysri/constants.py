"""Constantes del SRI (Servicio de Rentas Internas del Ecuador)."""
from decimal import Decimal

SRI_URLS = {
    # ambiente "1" = pruebas, "2" = producción
    "1": {
        "reception": "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline",
        "authorization": "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline",
    },
    "2": {
        "reception": "https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline",
        "authorization": "https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline",
    },
}

#: Identificación obligatoria para "venta a consumidor final".
CONSUMIDOR_FINAL_ID = "9999999999999"
#: Monto máximo permitido para facturas a consumidor final (USD).
#: Verifique la resolución vigente del SRI antes de usar en producción.
CONSUMIDOR_FINAL_MAX = Decimal("50.00")

#: Tolerancia de redondeo para validar totales.
TOLERANCE = Decimal("0.01")

#: Tarifas de IVA por código de porcentaje (tabla 17 de la ficha técnica).
#: El código 8 (IVA diferenciado) tiene tarifa variable y no se valida.
IVA_RATES = {
    "0": Decimal("0"),
    "2": Decimal("12"),
    "3": Decimal("14"),
    "4": Decimal("15"),
    "5": Decimal("5"),
    "6": Decimal("0"),
    "7": Decimal("0"),
    "10": Decimal("13"),
}

#: Códigos de mensaje del SRI en recepción que indican que el comprobante
#: ya fue recibido previamente ("CLAVE ACCESO REGISTRADA" / en procesamiento).
ALREADY_RECEIVED_CODES = {"43", "70"}
