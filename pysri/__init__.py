"""PySRI: facturación electrónica del SRI (Ecuador) con Python."""
from pysri.exceptions import (
    CertificateError,
    InvalidXMLError,
    PySRIError,
    SignatureError,
    SRIConnectionError,
    SRIResponseError,
)
from pysri.schemas.common import AmbienteType
from pysri.schemas.invoice import Invoice
from pysri.services.invoice import InvoiceResult, sign_invoice, sign_invoice_and_authorize
from pysri.services.sri import SRIClient
from pysri.signing.xades import load_p12, sign_xml
from pysri.utils.access_key import generate_access_key, is_valid_access_key
from pysri.utils.xml import dict_to_xml, xml_to_dict

__version__ = "0.2.0"

__all__ = [
    "AmbienteType",
    "CertificateError",
    "InvalidXMLError",
    "Invoice",
    "InvoiceResult",
    "PySRIError",
    "SRIClient",
    "SRIConnectionError",
    "SRIResponseError",
    "SignatureError",
    "dict_to_xml",
    "generate_access_key",
    "is_valid_access_key",
    "load_p12",
    "sign_invoice",
    "sign_invoice_and_authorize",
    "sign_xml",
    "xml_to_dict",
]
