# PySRI

Facturación electrónica del SRI (Ecuador) con Python: validación de facturas,
clave de acceso, firma **XAdES-BES**, envío a **Recepción** y consulta de
**Autorización**, más una **aplicación web** (API REST + interfaz) segura.

## Instalación

```bash
pip install -r requirements.txt          # o: pipenv install
pip install -r requirements-dev.txt      # pruebas (incluye xmlsec para verificar firmas)
```

Requiere Python 3.11 o superior.

## Uso como librería

```python
from pysri import AmbienteType, Invoice, sign_invoice_and_authorize

with open("firma.p12", "rb") as f:
    p12 = f.read()

factura = {
    "infoTributaria": {
        "ambiente": "1",                      # 1 = pruebas, 2 = producción
        "razonSocial": "EMPRESA DE PRUEBA S.A.",
        "ruc": "1712345675001",
        "estab": "001", "ptoEmi": "001", "secuencial": "1",
        "dirMatriz": "Av. Amazonas N1-23, Quito",
    },
    "infoFactura": {
        "fechaEmision": "2024-03-01",          # o "01/03/2024"
        "tipoIdentificacionComprador": "05",
        "razonSocialComprador": "JUAN PEREZ",
        "identificacionComprador": "0923456784",
        "totalSinImpuestos": "20.00",
        "totalDescuento": "0.00",
        "totalConImpuestos": [{"codigo": "2", "codigoPorcentaje": "4", "baseImponible": "20.00", "valor": "3.00"}],
        "importeTotal": "23.00",
        "pagos": [{"formaPago": "01", "total": "23.00"}],
    },
    "detalles": [{
        "codigoPrincipal": "P001", "descripcion": "Producto",
        "cantidad": "2", "precioUnitario": "10.00", "precioTotalSinImpuesto": "20.00",
        "impuestos": [{"codigo": "2", "codigoPorcentaje": "4", "tarifa": "15", "baseImponible": "20.00", "valor": "3.00"}],
    }],
}

result = sign_invoice_and_authorize(p12, "contraseña", factura, AmbienteType.PRUEBAS)
print(result.access_key, result.reception.estado, result.authorized)
```

Otras funciones: `Invoice.model_validate(...).to_xml()`, `sign_xml(p12, password, xml)`,
`load_p12(...)`, `SRIClient(ambiente).authorize(clave)`, `generate_access_key(...)`,
`is_valid_access_key(...)`.

### Validaciones del modelo `Invoice`

- Estructura según la ficha técnica (factura v1.1.0); campos desconocidos se rechazan.
- RUC del emisor, cédula/RUC del comprador, consumidor final (`9999999999999`, monto máximo).
- Clave de acceso generada (módulo 11) o, si se envía, verificada contra los datos de la factura.
- Cuadre de totales: líneas, descuentos, impuestos por tarifa, importe total y pagos (tolerancia 0.01).
- Tarifas de IVA por código, máximo de decimales, fechas no futuras, textos sin caracteres de control.

## Aplicación web

```bash
python -m web.keys                        # genera una API key y su hash
cp .env.example .env                      # configure PYSRI_API_KEY_HASHES, PYSRI_ALLOWED_HOSTS...
set -a; source .env; set +a
uvicorn web.main:app --host 127.0.0.1 --port 8000 --no-server-header
```

Desarrollo (sin API key, con `/docs`):

```bash
PYSRI_ENV=development PYSRI_AUTH_DISABLED=true uvicorn web.main:app --reload
```

Docker:

```bash
docker build -t pysri .
docker run --env-file .env -p 8000:8000 pysri
```

Abra `http://localhost:8000/` para usar la interfaz.

### Endpoints (`X-API-Key` requerido salvo `health`)

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/v1/health` | Estado del servicio |
| POST | `/api/v1/invoices/validate` | Valida la factura (JSON) y devuelve clave de acceso + XML |
| POST | `/api/v1/invoices/sign` | multipart: `certificate` (.p12), `password`, `invoice` (JSON) → XML firmado |
| POST | `/api/v1/invoices/send` | Igual que `sign` + envío a Recepción + Autorización |
| GET | `/api/v1/invoices/{clave}/authorization` | Consulta la autorización en el SRI |
| POST | `/api/v1/tools/identification` | Valida cédula / RUC / pasaporte |

### Seguridad

- **Autenticación** por API key (`X-API-Key`); solo se guardan hashes SHA-256 y se comparan en tiempo constante.
  La app no arranca en producción sin claves configuradas.
- **Rate limiting** por IP y por API key (más estricto en firma/envío). En memoria: con varios
  workers o réplicas use además el límite del proxy inverso o Redis.
- **Certificado y contraseña** se procesan solo en memoria; nunca se guardan ni se registran.
  Se rechazan certificados caducados y archivos que no sean `.p12/.pfx` o superen el tamaño máximo.
- **Errores** sin trazas ni eco de los datos enviados (la contraseña nunca aparece en respuestas).
- **XML endurecido**: sin DTD, entidades externas ni acceso a red (previene XXE / billion laughs).
- **Cabeceras**: CSP estricta, HSTS, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Cache-Control: no-store` en la API.
- **TrustedHost**, límite de tamaño del cuerpo, CORS cerrado por defecto, `/docs` deshabilitado en producción.
- **Producción del SRI** bloqueada por defecto (`PYSRI_ALLOW_PRODUCTION=false`).
- Ejecute siempre detrás de HTTPS (proxy inverso: Nginx, Caddy, Traefik…). Active
  `PYSRI_TRUST_PROXY_HEADERS` solo si ese proxy es de confianza.

## Pruebas

```bash
pytest
```

Las firmas se verifican con **xmlsec** (libxmlsec1), una implementación independiente.
Las llamadas al SRI se prueban con respuestas simuladas; antes de producción haga
pruebas reales en el ambiente de pruebas (`celcer.sri.gob.ec`) con su certificado.
