"""Modelo de factura electrónica (codDoc 01) según la ficha técnica del SRI, versión 1.1.0."""
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal
from typing import Annotated, Literal, Optional

from lxml import etree
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StringConstraints, field_validator, model_validator

from pysri.constants import CONSUMIDOR_FINAL_ID, CONSUMIDOR_FINAL_MAX, IVA_RATES, TOLERANCE
from pysri.schemas.common import (
    AmbienteType,
    BinaryResponseType,
    DocumentIdentificationType,
    EmissionType,
    PaymentMethod,
    TaxType,
)
from pysri.utils.access_key import generate_access_key, is_valid_access_key, parse_access_key
from pysri.utils.identification import is_valid_cedula, is_valid_ruc
from pysri.utils.xml import serialize

ECUADOR_TZ = timezone(timedelta(hours=-5))

# Texto sin caracteres de control (salvo tab/saltos de línea).
_SAFE_TEXT = r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*$"


def _zfill(length: int):
    def pad(value):
        if isinstance(value, int) and not isinstance(value, bool):
            value = str(value)
        if isinstance(value, str) and value.isdigit() and len(value) < length:
            return value.zfill(length)
        return value
    return BeforeValidator(pad)


Text300 = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300, pattern=_SAFE_TEXT)]
Code25 = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=25, pattern=_SAFE_TEXT)]
Estab = Annotated[str, _zfill(3), StringConstraints(pattern=r"^\d{3}$")]
Secuencial = Annotated[str, _zfill(9), StringConstraints(pattern=r"^\d{9}$")]
Money = Annotated[Decimal, Field(ge=0, max_digits=14, decimal_places=2)]
Quantity = Annotated[Decimal, Field(ge=0, max_digits=18, decimal_places=6)]
Rate = Annotated[Decimal, Field(ge=0, le=100, max_digits=5, decimal_places=2)]


def _fmt(value: Decimal, places: int = 2) -> str:
    return str(value.quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP))


def _round2(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _close(a: Decimal, b: Decimal) -> bool:
    return abs(a - b) <= TOLERANCE


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, validate_assignment=False)


class InfoTributaria(_Base):
    ambiente: AmbienteType = AmbienteType.PRUEBAS
    tipoEmision: EmissionType = EmissionType.NORMAL
    razonSocial: Text300
    nombreComercial: Optional[Text300] = None
    ruc: str
    claveAcceso: Optional[str] = None
    codDoc: Literal["01"] = "01"
    estab: Estab
    ptoEmi: Estab
    secuencial: Secuencial
    dirMatriz: Text300
    agenteRetencion: Optional[Annotated[str, StringConstraints(pattern=r"^\d{1,8}$")]] = None
    contribuyenteRimpe: Optional[
        Literal["CONTRIBUYENTE RÉGIMEN RIMPE", "CONTRIBUYENTE NEGOCIO POPULAR - RÉGIMEN RIMPE"]
    ] = None

    @field_validator("ruc")
    @classmethod
    def _ruc(cls, v: str) -> str:
        if not is_valid_ruc(v):
            raise ValueError("RUC del emisor inválido")
        return v

    @field_validator("estab", "ptoEmi")
    @classmethod
    def _non_zero3(cls, v: str) -> str:
        if v == "000":
            raise ValueError("no puede ser 000")
        return v

    @field_validator("secuencial")
    @classmethod
    def _non_zero9(cls, v: str) -> str:
        if int(v) == 0:
            raise ValueError("el secuencial no puede ser 0")
        return v

    @field_validator("claveAcceso")
    @classmethod
    def _clave(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not is_valid_access_key(v):
            raise ValueError("clave de acceso inválida (49 dígitos con dígito verificador módulo 11)")
        return v


class TotalImpuesto(_Base):
    codigo: TaxType
    codigoPorcentaje: Annotated[str, StringConstraints(pattern=r"^\d{1,4}$")]
    descuentoAdicional: Optional[Money] = None
    baseImponible: Money
    valor: Money


class Pago(_Base):
    formaPago: PaymentMethod
    total: Money
    plazo: Optional[Annotated[Decimal, Field(ge=0, max_digits=14, decimal_places=2)]] = None
    unidadTiempo: Optional[Annotated[str, StringConstraints(min_length=1, max_length=10, pattern=_SAFE_TEXT)]] = None


class InfoFactura(_Base):
    fechaEmision: date
    dirEstablecimiento: Optional[Text300] = None
    contribuyenteEspecial: Optional[Annotated[str, StringConstraints(min_length=3, max_length=13, pattern=r"^[0-9A-Za-z]+$")]] = None
    obligadoContabilidad: Optional[BinaryResponseType] = None
    tipoIdentificacionComprador: DocumentIdentificationType
    guiaRemision: Optional[Annotated[str, StringConstraints(pattern=r"^\d{3}-\d{3}-\d{9}$")]] = None
    razonSocialComprador: Text300
    identificacionComprador: Annotated[str, StringConstraints(min_length=1, max_length=20, pattern=r"^[0-9A-Za-z-]+$")]
    direccionComprador: Optional[Text300] = None
    totalSinImpuestos: Money
    totalDescuento: Money = Decimal("0")
    totalConImpuestos: list[TotalImpuesto] = Field(min_length=1, max_length=50)
    propina: Money = Decimal("0")
    importeTotal: Money
    moneda: Literal["DOLAR"] = "DOLAR"
    pagos: list[Pago] = Field(min_length=1, max_length=20)

    @field_validator("fechaEmision", mode="before")
    @classmethod
    def _fecha(cls, v):
        if isinstance(v, str) and len(v) == 10 and v[2] == "/" and v[5] == "/":
            try:
                return datetime.strptime(v, "%d/%m/%Y").date()
            except ValueError:
                raise ValueError("fecha inválida, use dd/mm/aaaa o aaaa-mm-dd") from None
        return v

    @field_validator("fechaEmision")
    @classmethod
    def _fecha_no_futura(cls, v: date) -> date:
        if v > datetime.now(ECUADOR_TZ).date():
            raise ValueError("la fecha de emisión no puede ser futura")
        return v

    @model_validator(mode="after")
    def _comprador(self):
        tipo = self.tipoIdentificacionComprador
        ident = self.identificacionComprador
        if tipo == DocumentIdentificationType.RUC and not is_valid_ruc(ident):
            raise ValueError("identificacionComprador: RUC inválido")
        if tipo == DocumentIdentificationType.CEDULA and not is_valid_cedula(ident):
            raise ValueError("identificacionComprador: cédula inválida")
        if tipo == DocumentIdentificationType.VENTA_A_CONSUMIDOR_FINAL:
            if ident != CONSUMIDOR_FINAL_ID:
                raise ValueError(f"identificacionComprador: para consumidor final debe ser {CONSUMIDOR_FINAL_ID}")
            if self.importeTotal > CONSUMIDOR_FINAL_MAX:
                raise ValueError(
                    f"importeTotal: las facturas a consumidor final no pueden superar {CONSUMIDOR_FINAL_MAX} USD"
                )
        if tipo == DocumentIdentificationType.PASAPORTE and len(ident) < 3:
            raise ValueError("identificacionComprador: pasaporte inválido")
        return self


class Impuesto(_Base):
    codigo: TaxType
    codigoPorcentaje: Annotated[str, StringConstraints(pattern=r"^\d{1,4}$")]
    tarifa: Rate
    baseImponible: Money
    valor: Money

    @model_validator(mode="after")
    def _check(self):
        if self.codigo == TaxType.IVA:
            expected_rate = IVA_RATES.get(self.codigoPorcentaje)
            if expected_rate is None and self.codigoPorcentaje != "8":
                raise ValueError(f"codigoPorcentaje de IVA desconocido: {self.codigoPorcentaje}")
            if expected_rate is not None and self.tarifa != expected_rate:
                raise ValueError(
                    f"la tarifa de IVA para el código {self.codigoPorcentaje} debe ser {expected_rate}"
                )
            if not _close(self.valor, _round2(self.baseImponible * self.tarifa / 100)):
                raise ValueError("valor del impuesto no coincide con baseImponible × tarifa")
        return self


class DetAdicional(_Base):
    nombre: Annotated[str, StringConstraints(min_length=1, max_length=300, pattern=_SAFE_TEXT)]
    valor: Annotated[str, StringConstraints(min_length=1, max_length=300, pattern=_SAFE_TEXT)]


class Detalle(_Base):
    codigoPrincipal: Code25
    codigoAuxiliar: Optional[Code25] = None
    descripcion: Text300
    cantidad: Quantity
    precioUnitario: Quantity
    descuento: Money = Decimal("0")
    precioTotalSinImpuesto: Money
    detallesAdicionales: Optional[list[DetAdicional]] = Field(default=None, max_length=3)
    impuestos: list[Impuesto] = Field(min_length=1, max_length=10)

    @field_validator("cantidad")
    @classmethod
    def _cantidad(cls, v: Decimal) -> Decimal:
        if v <= 0:
            raise ValueError("la cantidad debe ser mayor a 0")
        return v

    @model_validator(mode="after")
    def _check(self):
        bruto = self.cantidad * self.precioUnitario
        if self.descuento > _round2(bruto) + TOLERANCE:
            raise ValueError("el descuento no puede ser mayor al subtotal de la línea")
        if not _close(self.precioTotalSinImpuesto, _round2(bruto - self.descuento)):
            raise ValueError("precioTotalSinImpuesto debe ser cantidad × precioUnitario − descuento")
        ice = sum((i.valor for i in self.impuestos if i.codigo == TaxType.ICE), Decimal("0"))
        seen = set()
        for imp in self.impuestos:
            if imp.codigo in seen:
                raise ValueError(f"impuesto {imp.codigo} repetido en el detalle")
            seen.add(imp.codigo)
            expected_base = self.precioTotalSinImpuesto + (ice if imp.codigo == TaxType.IVA else 0)
            if imp.codigo != TaxType.IRBPNR and not _close(imp.baseImponible, expected_base):
                raise ValueError("baseImponible del impuesto no coincide con el precio total de la línea")
        if TaxType.IVA not in seen:
            raise ValueError("cada detalle debe incluir el impuesto IVA (código 2)")
        return self


class CampoAdicional(_Base):
    nombre: Annotated[str, StringConstraints(min_length=1, max_length=300, pattern=_SAFE_TEXT)]
    valor: Annotated[str, StringConstraints(min_length=1, max_length=300, pattern=_SAFE_TEXT)]


class Invoice(_Base):
    """Factura electrónica. Valida estructura, identificaciones y cuadre de totales."""

    version: Literal["1.1.0"] = "1.1.0"
    infoTributaria: InfoTributaria
    infoFactura: InfoFactura
    detalles: list[Detalle] = Field(min_length=1, max_length=1000)
    infoAdicional: Optional[list[CampoAdicional]] = Field(default=None, max_length=15)

    @model_validator(mode="after")
    def _totals(self):
        info = self.infoFactura
        detalles = self.detalles

        subtotal = sum((d.precioTotalSinImpuesto for d in detalles), Decimal("0"))
        if not _close(info.totalSinImpuestos, subtotal):
            raise ValueError(f"totalSinImpuestos ({info.totalSinImpuestos}) no coincide con la suma de los detalles ({subtotal})")

        adicional = sum((t.descuentoAdicional or Decimal("0") for t in info.totalConImpuestos), Decimal("0"))
        descuentos = sum((d.descuento for d in detalles), Decimal("0")) + adicional
        if not _close(info.totalDescuento, descuentos):
            raise ValueError(f"totalDescuento ({info.totalDescuento}) no coincide con los descuentos ({descuentos})")

        agrupado: dict[tuple[str, str], list[Decimal]] = defaultdict(lambda: [Decimal("0"), Decimal("0")])
        for d in detalles:
            for imp in d.impuestos:
                agrupado[(imp.codigo, imp.codigoPorcentaje)][0] += imp.baseImponible
                agrupado[(imp.codigo, imp.codigoPorcentaje)][1] += imp.valor

        declarados = {}
        for t in info.totalConImpuestos:
            key = (t.codigo, t.codigoPorcentaje)
            if key in declarados:
                raise ValueError(f"totalConImpuestos repite el impuesto {key}")
            declarados[key] = t
        if set(declarados) != set(agrupado):
            raise ValueError("totalConImpuestos no corresponde a los impuestos de los detalles")
        for key, t in declarados.items():
            base, valor = agrupado[key]
            if not _close(t.baseImponible, base - (t.descuentoAdicional or 0)):
                raise ValueError(f"baseImponible del total de impuesto {key} no cuadra con los detalles")
            # Se acepta la suma de las líneas o el cálculo sobre la base total
            # (pueden diferir por redondeo cuando hay muchas líneas).
            ok = _close(t.valor, valor)
            if not ok and t.codigo == TaxType.IVA and t.codigoPorcentaje in IVA_RATES:
                ok = _close(t.valor, _round2(t.baseImponible * IVA_RATES[t.codigoPorcentaje] / 100))
            if not ok:
                raise ValueError(f"valor del total de impuesto {key} no cuadra con los detalles")

        impuestos = sum((t.valor for t in info.totalConImpuestos), Decimal("0"))
        esperado_total = info.totalSinImpuestos - adicional + impuestos + info.propina
        if not _close(info.importeTotal, esperado_total):
            raise ValueError(f"importeTotal ({info.importeTotal}) debe ser {_round2(esperado_total)}")

        pagado = sum((p.total for p in info.pagos), Decimal("0"))
        if not _close(pagado, info.importeTotal):
            raise ValueError(f"la suma de pagos ({pagado}) no coincide con importeTotal ({info.importeTotal})")

        self._ensure_access_key()
        return self

    def _ensure_access_key(self) -> None:
        it = self.infoTributaria
        fecha = self.infoFactura.fechaEmision
        if it.claveAcceso is None:
            it.claveAcceso = generate_access_key(
                fecha, it.codDoc, it.ruc, it.ambiente.value, it.estab, it.ptoEmi, it.secuencial,
                tipo_emision=it.tipoEmision.value,
            )
            return
        p = parse_access_key(it.claveAcceso)
        expected = (fecha, it.codDoc, it.ruc, it.ambiente.value, it.estab, it.ptoEmi, it.secuencial, it.tipoEmision.value)
        actual = (p.fecha_emision, p.cod_doc, p.ruc, p.ambiente, p.estab, p.pto_emi, p.secuencial, p.tipo_emision)
        if expected != actual:
            raise ValueError("la claveAcceso no coincide con fecha, RUC, ambiente, establecimiento, punto de emisión o secuencial")

    @property
    def access_key(self) -> str:
        assert self.infoTributaria.claveAcceso is not None
        return self.infoTributaria.claveAcceso

    # ------------------------------------------------------------------ XML
    def to_xml(self) -> bytes:
        """Genera el XML (sin firmar) listo para firmar con XAdES-BES."""

        def sub(parent, tag, value):
            if value is None:
                return None
            el = etree.SubElement(parent, tag)
            if isinstance(value, Decimal):
                el.text = _fmt(value)
            else:
                el.text = str(value.value if hasattr(value, "value") else value)
            return el

        root = etree.Element("factura", id="comprobante", version=self.version)

        it = self.infoTributaria
        n = etree.SubElement(root, "infoTributaria")
        for tag in ("ambiente", "tipoEmision", "razonSocial", "nombreComercial", "ruc", "claveAcceso",
                    "codDoc", "estab", "ptoEmi", "secuencial", "dirMatriz", "agenteRetencion", "contribuyenteRimpe"):
            sub(n, tag, getattr(it, tag))

        f = self.infoFactura
        n = etree.SubElement(root, "infoFactura")
        sub(n, "fechaEmision", f.fechaEmision.strftime("%d/%m/%Y"))
        for tag in ("dirEstablecimiento", "contribuyenteEspecial", "obligadoContabilidad",
                    "tipoIdentificacionComprador", "guiaRemision", "razonSocialComprador",
                    "identificacionComprador", "direccionComprador", "totalSinImpuestos", "totalDescuento"):
            sub(n, tag, getattr(f, tag))
        tci = etree.SubElement(n, "totalConImpuestos")
        for t in f.totalConImpuestos:
            ti = etree.SubElement(tci, "totalImpuesto")
            for tag in ("codigo", "codigoPorcentaje", "descuentoAdicional", "baseImponible", "valor"):
                sub(ti, tag, getattr(t, tag))
        sub(n, "propina", f.propina)
        sub(n, "importeTotal", f.importeTotal)
        sub(n, "moneda", f.moneda)
        pagos = etree.SubElement(n, "pagos")
        for p in f.pagos:
            pe = etree.SubElement(pagos, "pago")
            sub(pe, "formaPago", p.formaPago)
            sub(pe, "total", p.total)
            if p.plazo is not None:
                sub(pe, "plazo", p.plazo)
            sub(pe, "unidadTiempo", p.unidadTiempo)

        dets = etree.SubElement(root, "detalles")
        for d in self.detalles:
            de = etree.SubElement(dets, "detalle")
            sub(de, "codigoPrincipal", d.codigoPrincipal)
            sub(de, "codigoAuxiliar", d.codigoAuxiliar)
            sub(de, "descripcion", d.descripcion)
            etree.SubElement(de, "cantidad").text = _fmt(d.cantidad, 6)
            etree.SubElement(de, "precioUnitario").text = _fmt(d.precioUnitario, 6)
            sub(de, "descuento", d.descuento)
            sub(de, "precioTotalSinImpuesto", d.precioTotalSinImpuesto)
            if d.detallesAdicionales:
                da = etree.SubElement(de, "detallesAdicionales")
                for item in d.detallesAdicionales:
                    etree.SubElement(da, "detAdicional", nombre=item.nombre, valor=item.valor)
            imps = etree.SubElement(de, "impuestos")
            for imp in d.impuestos:
                ie = etree.SubElement(imps, "impuesto")
                sub(ie, "codigo", imp.codigo)
                sub(ie, "codigoPorcentaje", imp.codigoPorcentaje)
                sub(ie, "tarifa", imp.tarifa)
                sub(ie, "baseImponible", imp.baseImponible)
                sub(ie, "valor", imp.valor)

        if self.infoAdicional:
            ia = etree.SubElement(root, "infoAdicional")
            for campo in self.infoAdicional:
                etree.SubElement(ia, "campoAdicional", nombre=campo.nombre).text = campo.valor

        return serialize(root)
