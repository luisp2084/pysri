from enum import StrEnum


class AmbienteType(StrEnum):
    PRUEBAS = "1"
    PRODUCCION = "2"


class EmissionType(StrEnum):
    NORMAL = "1"


class BinaryResponseType(StrEnum):
    SI = "SI"
    NO = "NO"


class DocumentIdentificationType(StrEnum):
    RUC = "04"
    CEDULA = "05"
    PASAPORTE = "06"
    VENTA_A_CONSUMIDOR_FINAL = "07"
    IDENTIFICACION_DEL_EXTERIOR = "08"


class DocumentType(StrEnum):
    FACTURA = "01"
    LIQUIDACION_DE_COMPRA_DE_BIENES_Y_PRESTACION_DE_SERVICIOS = "03"
    NOTA_DE_CREDITO = "04"
    NOTA_DE_DEBITO = "05"
    GUIA_DE_REMISION = "06"
    COMPROBANTE_DE_RETENCION = "07"


class TaxType(StrEnum):
    IVA = "2"
    ICE = "3"
    IRBPNR = "5"


class PaymentMethod(StrEnum):
    SIN_UTILIZACION_SISTEMA_FINANCIERO = "01"
    COMPENSACION_DE_DEUDAS = "15"
    TARJETA_DE_DEBITO = "16"
    DINERO_ELECTRONICO = "17"
    TARJETA_PREPAGO = "18"
    TARJETA_DE_CREDITO = "19"
    OTROS_CON_UTILIZACION_SISTEMA_FINANCIERO = "20"
    ENDOSO_DE_TITULOS = "21"
