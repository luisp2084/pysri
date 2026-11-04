"""API web de PySRI.

Ejecutar en desarrollo::

    PYSRI_ENV=development PYSRI_AUTH_DISABLED=true uvicorn web.main:app --reload
"""
import logging
from pathlib import Path
from typing import Annotated, Any, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Path as PathParam, Query, Request, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from pysri.constants import ALREADY_RECEIVED_CODES
from pysri.exceptions import CertificateError, InvalidXMLError, PySRIError, SRIConnectionError, SRIResponseError
from pysri.schemas.common import AmbienteType, DocumentIdentificationType
from pysri.schemas.invoice import Invoice
from pysri.services.sri import AuthorizationResponse, ReceptionResponse, SRIClient
from pysri.signing.xades import load_p12, sign_xml
from pysri.utils.access_key import is_valid_access_key
from pysri.utils.identification import is_valid_cedula, is_valid_ruc
from web.config import Settings
from web.security import (
    BodySizeLimitMiddleware,
    RateLimiter,
    SecurityHeadersMiddleware,
    authenticate,
    client_ip,
)

logger = logging.getLogger("pysri.web")
STATIC_DIR = Path(__file__).parent / "static"
MAX_INVOICE_JSON = 512 * 1024


# ----------------------------------------------------------------- respuestas
class ValidateResponse(BaseModel):
    accessKey: str
    xml: str


class SignResponse(BaseModel):
    accessKey: str
    signedXml: str
    certificateSubject: str
    certificateExpires: str


class MessageOut(BaseModel):
    identificador: Optional[str] = None
    mensaje: Optional[str] = None
    informacionAdicional: Optional[str] = None
    tipo: Optional[str] = None


class ReceptionOut(BaseModel):
    estado: str
    mensajes: list[MessageOut] = []


class AuthorizationOut(BaseModel):
    estado: str
    numeroAutorizacion: Optional[str] = None
    fechaAutorizacion: Optional[str] = None
    ambiente: Optional[str] = None
    comprobante: Optional[str] = None
    mensajes: list[MessageOut] = []


class SendResponse(BaseModel):
    accessKey: str
    signedXml: str
    reception: ReceptionOut
    authorization: Optional[AuthorizationOut] = None
    authorized: bool


class IdentificationIn(BaseModel):
    tipo: DocumentIdentificationType
    numero: str = Field(min_length=1, max_length=20)


def _reception_out(r: ReceptionResponse) -> ReceptionOut:
    return ReceptionOut(estado=r.estado, mensajes=[MessageOut(**m.__dict__) for m in r.mensajes])


def _authorization_out(r: Optional[AuthorizationResponse]) -> Optional[AuthorizationOut]:
    a = r.latest if r else None
    if a is None:
        return None
    return AuthorizationOut(
        estado=a.estado, numeroAutorizacion=a.numero_autorizacion, fechaAutorizacion=a.fecha_autorizacion,
        ambiente=a.ambiente, comprobante=a.comprobante, mensajes=[MessageOut(**m.__dict__) for m in a.mensajes],
    )


def _clean_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Quita 'input'/'ctx'/'url' de los errores para no reflejar datos sensibles (p. ej. contraseñas)."""
    out = []
    for e in errors:
        loc = [str(p) for p in e.get("loc", ()) if p not in ("body",)]
        msg = str(e.get("msg", "valor inválido")).removeprefix("Value error, ")
        out.append({"campo": ".".join(loc), "error": msg})
    return out


# ----------------------------------------------------------------- app
def create_app(settings: Optional[Settings] = None, sri_client_factory=None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate()
    if not settings.auth_enabled:
        logger.warning("Autenticación DESHABILITADA (solo desarrollo)")

    app = FastAPI(
        title="PySRI",
        version="0.2.0",
        description="Facturación electrónica SRI Ecuador: validación, firma XAdES-BES y envío.",
        docs_url="/docs" if settings.is_development else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.is_development else None,
    )
    app.state.settings = settings
    make_client = sri_client_factory or (
        lambda ambiente: SRIClient(ambiente, timeout=settings.sri_timeout, verify_tls=settings.sri_verify_tls)
    )

    # El orden importa: el último middleware agregado es el más externo.
    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["GET", "POST"],
                           allow_headers=["X-API-Key", "Content-Type"], allow_credentials=False, max_age=600)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts or ["localhost"])
    app.add_middleware(SecurityHeadersMiddleware, hsts=not settings.is_development)

    general_limiter = RateLimiter(settings.rate_limit_per_minute)
    sensitive_limiter = RateLimiter(settings.sensitive_rate_limit_per_minute)

    def auth(request: Request) -> str:
        ip = client_ip(request, settings)
        # Limitar también intentos fallidos de autenticación por IP.
        general_limiter.check(f"ip:{ip}")
        return authenticate(request, settings)

    def sensitive(request: Request, who: str = Depends(auth)) -> str:
        sensitive_limiter.check(f"key:{who}:{client_ip(request, settings)}")
        return who

    Auth = Annotated[str, Depends(auth)]
    Sensitive = Annotated[str, Depends(sensitive)]

    # ------------------------------------------------------------- errores
    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        return JSONResponse(status_code=422, content={"detail": "Datos inválidos", "errores": _clean_errors(exc.errors())})

    @app.exception_handler(CertificateError)
    async def _cert(_: Request, exc: CertificateError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(InvalidXMLError)
    async def _xml(_: Request, exc: InvalidXMLError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(SRIConnectionError)
    async def _sri_conn(_: Request, exc: SRIConnectionError):
        logger.warning("Error de conexión con el SRI: %s", exc)
        return JSONResponse(status_code=502, content={"detail": "No se pudo comunicar con el SRI, intente más tarde"})

    @app.exception_handler(SRIResponseError)
    async def _sri_resp(_: Request, exc: SRIResponseError):
        logger.warning("Respuesta inválida del SRI: %s", exc)
        return JSONResponse(status_code=502, content={"detail": str(exc)})

    @app.exception_handler(PySRIError)
    async def _pysri(_: Request, exc: PySRIError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        logger.exception("Error no controlado en %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Error interno del servidor"})

    # ------------------------------------------------------------- helpers
    def check_ambiente(ambiente: AmbienteType) -> None:
        if ambiente == AmbienteType.PRODUCCION and not settings.allow_production:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "El ambiente de PRODUCCIÓN está deshabilitado en este servidor")

    def parse_invoice(raw: str) -> Invoice:
        if len(raw.encode("utf-8")) > MAX_INVOICE_JSON:
            raise HTTPException(413, "La factura es demasiado grande")
        try:
            invoice = Invoice.model_validate_json(raw)
        except ValidationError as exc:
            raise RequestValidationError([{**e, "loc": ("invoice", *e["loc"])} for e in exc.errors()]) from None
        check_ambiente(invoice.infoTributaria.ambiente)
        return invoice

    async def read_certificate(upload: UploadFile) -> bytes:
        name = (upload.filename or "").lower()
        if not name.endswith((".p12", ".pfx")):
            raise HTTPException(400, "El certificado debe ser un archivo .p12 o .pfx")
        data = await upload.read(settings.max_cert_bytes + 1)
        await upload.close()
        if not data:
            raise HTTPException(400, "El archivo de certificado está vacío")
        if len(data) > settings.max_cert_bytes:
            raise HTTPException(413, "El archivo de certificado es demasiado grande")
        return data

    async def do_sign(certificate: UploadFile, password: str, invoice_raw: str):
        invoice = parse_invoice(invoice_raw)
        p12 = await read_certificate(certificate)
        try:
            creds = await run_in_threadpool(load_p12, p12, password)
            signed = await run_in_threadpool(sign_xml, p12, password, invoice.to_xml(), credentials=creds)
        finally:
            # No conservar el certificado ni la contraseña más de lo necesario.
            del p12, password
        return invoice, signed, creds

    # ------------------------------------------------------------- rutas
    @app.get("/api/v1/health", tags=["sistema"])
    async def health():
        return {"status": "ok"}

    @app.get("/api/v1/config", tags=["sistema"])
    async def public_config(_: Auth):
        return {"allowProduction": settings.allow_production, "environment": settings.env}

    @app.post("/api/v1/invoices/validate", response_model=ValidateResponse, tags=["facturas"])
    async def validate_invoice(invoice: Invoice, _: Auth):
        """Valida la factura (estructura, identificaciones, cuadre de totales) y devuelve el XML sin firmar."""
        check_ambiente(invoice.infoTributaria.ambiente)
        return ValidateResponse(accessKey=invoice.access_key, xml=invoice.to_xml().decode("utf-8"))

    @app.post("/api/v1/invoices/sign", response_model=SignResponse, tags=["facturas"])
    async def sign_invoice_endpoint(
        _: Sensitive,
        certificate: Annotated[UploadFile, File(description="Certificado de firma .p12/.pfx")],
        password: Annotated[str, Form(min_length=1, max_length=256)],
        invoice: Annotated[str, Form(description="Factura en JSON")],
    ):
        """Firma la factura con XAdES-BES. El certificado y la contraseña no se almacenan."""
        inv, signed, creds = await do_sign(certificate, password, invoice)
        return SignResponse(accessKey=inv.access_key, signedXml=signed.decode("utf-8"),
                            certificateSubject=creds.subject,
                            certificateExpires=creds.not_valid_after.isoformat())

    @app.post("/api/v1/invoices/send", response_model=SendResponse, tags=["facturas"])
    async def send_invoice_endpoint(
        _: Sensitive,
        certificate: Annotated[UploadFile, File(description="Certificado de firma .p12/.pfx")],
        password: Annotated[str, Form(min_length=1, max_length=256)],
        invoice: Annotated[str, Form(description="Factura en JSON")],
    ):
        """Firma, envía al SRI (recepción) y consulta la autorización."""
        inv, signed, _creds = await do_sign(certificate, password, invoice)
        client = make_client(inv.infoTributaria.ambiente)
        reception = await run_in_threadpool(client.send_receipt, signed)
        authorization = None
        already = any(m.identificador in ALREADY_RECEIVED_CODES for m in reception.mensajes)
        if reception.received or already:
            authorization = await run_in_threadpool(
                client.wait_for_authorization, inv.access_key,
                settings.sri_auth_attempts, settings.sri_auth_delay,
            )
        auth_out = _authorization_out(authorization)
        return SendResponse(
            accessKey=inv.access_key, signedXml=signed.decode("utf-8"),
            reception=_reception_out(reception), authorization=auth_out,
            authorized=bool(auth_out and auth_out.estado == "AUTORIZADO"),
        )

    @app.get("/api/v1/invoices/{access_key}/authorization", response_model=Optional[AuthorizationOut],
             tags=["facturas"])
    async def get_authorization(
        _: Sensitive,
        access_key: Annotated[str, PathParam(pattern=r"^\d{49}$")],
        ambiente: Annotated[Optional[AmbienteType], Query()] = None,
    ):
        """Consulta el estado de autorización de un comprobante en el SRI."""
        if not is_valid_access_key(access_key):
            raise HTTPException(422, "Clave de acceso inválida")
        amb = ambiente or AmbienteType(access_key[23])
        if amb.value != access_key[23]:
            raise HTTPException(422, "El ambiente no coincide con la clave de acceso")
        check_ambiente(amb)
        response = await run_in_threadpool(make_client(amb).authorize, access_key)
        out = _authorization_out(response)
        if out is None:
            raise HTTPException(404, "El SRI no tiene registros de este comprobante")
        return out

    @app.post("/api/v1/tools/identification", tags=["herramientas"])
    async def validate_identification(data: IdentificationIn, _: Auth):
        numero = data.numero.strip()
        if data.tipo == DocumentIdentificationType.RUC:
            valid = is_valid_ruc(numero)
        elif data.tipo == DocumentIdentificationType.CEDULA:
            valid = is_valid_cedula(numero)
        elif data.tipo == DocumentIdentificationType.VENTA_A_CONSUMIDOR_FINAL:
            valid = numero == "9999999999999"
        else:
            valid = 3 <= len(numero) <= 20 and numero.isalnum()
        return {"valid": valid}

    # ------------------------------------------------------------- frontend
    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


def __getattr__(name: str):
    # ``uvicorn web.main:app`` construye la app perezosamente (permite importar el
    # módulo en tests sin variables de entorno configuradas).
    if name == "app":
        global app
        app = create_app()
        return app
    raise AttributeError(name)
