"""Firma XAdES-BES (enveloped) de comprobantes electrónicos según la ficha técnica del SRI.

El SRI exige: XAdES-BES, RSA-SHA1, digest SHA1, canonicalización C14N 1.0 inclusiva
y que el nodo firmado tenga ``id="comprobante"``.
"""
import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from lxml import etree

from pysri.exceptions import CertificateError, InvalidXMLError, SignatureError
from pysri.utils.xml import parse_xml, serialize

DS_NS = "http://www.w3.org/2000/09/xmldsig#"
ETSI_NS = "http://uri.etsi.org/01903/v1.3.2#"
NSMAP = {"ds": DS_NS, "etsi": ETSI_NS}

C14N_ALG = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
SIGNED_PROPS_TYPE = "http://uri.etsi.org/01903#SignedProperties"

ECUADOR_TZ = timezone(timedelta(hours=-5))
MAX_P12_BYTES = 100 * 1024


@dataclass(frozen=True)
class SigningCredentials:
    private_key: rsa.RSAPrivateKey
    certificate: x509.Certificate

    @property
    def subject(self) -> str:
        return self.certificate.subject.rfc4514_string()

    @property
    def not_valid_after(self) -> datetime:
        return self.certificate.not_valid_after_utc


def load_p12(p12: bytes, password: bytes | str, *, check_validity: bool = True) -> SigningCredentials:
    """Carga la llave privada y el certificado de firma desde un archivo .p12/.pfx."""
    if not isinstance(p12, (bytes, bytearray)) or not p12:
        raise CertificateError("El certificado debe ser el contenido binario de un archivo .p12")
    if len(p12) > MAX_P12_BYTES:
        raise CertificateError("El archivo de certificado es demasiado grande")
    if isinstance(password, str):
        password = password.encode("utf-8")
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(bytes(p12), password or None)
    except Exception:  # noqa: BLE001 - no filtrar detalles (p. ej. contraseña)
        raise CertificateError("No se pudo abrir el certificado: archivo o contraseña incorrectos") from None
    if key is None:
        raise CertificateError("El archivo .p12 no contiene una llave privada")
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CertificateError("El SRI requiere una llave RSA")

    # Algunos .p12 (BCE, Security Data) traen varios certificados: se usa el que
    # corresponde a la llave privada, priorizando el de firma digital.
    pub = key.public_key().public_numbers()
    candidates = [c for c in [cert, *(extra or [])] if c is not None]
    matching = [c for c in candidates
                if isinstance(c.public_key(), rsa.RSAPublicKey) and c.public_key().public_numbers() == pub]
    if not matching:
        raise CertificateError("Ningún certificado del .p12 corresponde a la llave privada")

    def is_signing(c: x509.Certificate) -> bool:
        try:
            return c.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
        except x509.ExtensionNotFound:
            return True

    chosen = next((c for c in matching if is_signing(c)), matching[0])
    if check_validity:
        now = datetime.now(timezone.utc)
        if now < chosen.not_valid_before_utc:
            raise CertificateError("El certificado aún no es válido")
        if now > chosen.not_valid_after_utc:
            raise CertificateError("El certificado está caducado")
    return SigningCredentials(private_key=key, certificate=chosen)


def _c14n(element: etree._Element) -> bytes:
    return etree.tostring(element, method="c14n", exclusive=False, with_comments=False)


def _sha1_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha1(data).digest()).decode("ascii")  # noqa: S324 - exigido por el SRI


def _b64_int(value: int) -> str:
    return base64.b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).decode("ascii")


def _ds(parent, tag, text=None, **attrs):
    el = etree.SubElement(parent, f"{{{DS_NS}}}{tag}", **attrs)
    if text is not None:
        el.text = text
    return el


def _etsi(parent, tag, text=None, **attrs):
    el = etree.SubElement(parent, f"{{{ETSI_NS}}}{tag}", **attrs)
    if text is not None:
        el.text = text
    return el


def sign_xml(
    p12: bytes,
    password: bytes | str,
    xml: bytes | str,
    *,
    signing_time: datetime | None = None,
    credentials: SigningCredentials | None = None,
) -> bytes:
    """Firma un comprobante y devuelve el XML firmado (UTF-8, con declaración XML)."""
    creds = credentials or load_p12(p12, password)
    root = parse_xml(xml)
    if root.get("id") != "comprobante":
        raise InvalidXMLError('El nodo raíz del comprobante debe tener id="comprobante"')
    if root.find(f".//{{{DS_NS}}}Signature") is not None:
        raise InvalidXMLError("El comprobante ya está firmado")

    cert = creds.certificate
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    n = secrets.randbelow(900000) + 100000
    sig_id = f"Signature{n}"
    signed_props_id = f"{sig_id}-SignedProperties{n}"
    cert_id = f"Certificate{n}"
    ref_id = f"Reference-ID-{n}"
    when = (signing_time or datetime.now(ECUADOR_TZ)).astimezone(ECUADOR_TZ).replace(microsecond=0)

    # 1) Digest del comprobante (transformación enveloped: antes de insertar la firma).
    doc_digest = _sha1_b64(_c14n(root))

    # 2) Construir la estructura de la firma dentro del documento (para que el
    #    contexto de namespaces al canonicalizar sea el definitivo).
    signature = etree.SubElement(root, f"{{{DS_NS}}}Signature", nsmap=NSMAP, Id=sig_id)
    signed_info = _ds(signature, "SignedInfo", Id=f"Signature-SignedInfo{n}")
    _ds(signed_info, "CanonicalizationMethod", Algorithm=C14N_ALG)
    _ds(signed_info, "SignatureMethod", Algorithm=RSA_SHA1)
    ref_props = _ds(signed_info, "Reference", Id=f"SignedPropertiesID{n}", Type=SIGNED_PROPS_TYPE,
                    URI=f"#{signed_props_id}")
    _ds(ref_props, "DigestMethod", Algorithm=SHA1)
    props_digest_el = _ds(ref_props, "DigestValue")
    ref_cert = _ds(signed_info, "Reference", URI=f"#{cert_id}")
    _ds(ref_cert, "DigestMethod", Algorithm=SHA1)
    cert_digest_el = _ds(ref_cert, "DigestValue")
    ref_doc = _ds(signed_info, "Reference", Id=ref_id, URI="#comprobante")
    transforms = _ds(ref_doc, "Transforms")
    _ds(transforms, "Transform", Algorithm=ENVELOPED)
    _ds(ref_doc, "DigestMethod", Algorithm=SHA1)
    _ds(ref_doc, "DigestValue", doc_digest)

    sig_value_el = _ds(signature, "SignatureValue", Id=f"SignatureValue{n}")

    key_info = _ds(signature, "KeyInfo", Id=cert_id)
    x509_data = _ds(key_info, "X509Data")
    _ds(x509_data, "X509Certificate", base64.b64encode(cert_der).decode("ascii"))
    key_value = _ds(key_info, "KeyValue")
    rsa_kv = _ds(key_value, "RSAKeyValue")
    pub = creds.private_key.public_key().public_numbers()
    _ds(rsa_kv, "Modulus", _b64_int(pub.n))
    _ds(rsa_kv, "Exponent", _b64_int(pub.e))

    obj = _ds(signature, "Object", Id=f"{sig_id}-Object{n}")
    qp = _etsi(obj, "QualifyingProperties", Target=f"#{sig_id}")
    sp = _etsi(qp, "SignedProperties", Id=signed_props_id)
    ssp = _etsi(sp, "SignedSignatureProperties")
    _etsi(ssp, "SigningTime", when.isoformat())
    sc = _etsi(ssp, "SigningCertificate")
    c = _etsi(sc, "Cert")
    cd = _etsi(c, "CertDigest")
    _ds(cd, "DigestMethod", Algorithm=SHA1)
    _ds(cd, "DigestValue", _sha1_b64(cert_der))
    iss = _etsi(c, "IssuerSerial")
    _ds(iss, "X509IssuerName", cert.issuer.rfc4514_string())
    _ds(iss, "X509SerialNumber", str(cert.serial_number))
    sdop = _etsi(sp, "SignedDataObjectProperties")
    dof = _etsi(sdop, "DataObjectFormat", ObjectReference=f"#{ref_id}")
    _etsi(dof, "Description", "contenido comprobante")
    _etsi(dof, "MimeType", "text/xml")

    # 3) Digests de SignedProperties y KeyInfo, luego firma de SignedInfo.
    props_digest_el.text = _sha1_b64(_c14n(sp))
    cert_digest_el.text = _sha1_b64(_c14n(key_info))
    try:
        raw = creds.private_key.sign(_c14n(signed_info), padding.PKCS1v15(), hashes.SHA1())  # noqa: S303
    except Exception as exc:  # noqa: BLE001
        raise SignatureError("No se pudo generar la firma") from exc
    sig_value_el.text = base64.b64encode(raw).decode("ascii")

    return serialize(root)
