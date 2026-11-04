"""Autenticación por API key, rate limiting y middlewares de seguridad."""
import hashlib
import hmac
import threading
import time
from collections import deque

from fastapi import HTTPException, Request, status
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from web.config import Settings

API_KEY_HEADER = "X-API-Key"


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def client_ip(request: Request, settings: Settings) -> str:
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def authenticate(request: Request, settings: Settings) -> str:
    """Devuelve un identificador (no secreto) del cliente autenticado."""
    if not settings.auth_enabled:
        return "dev"
    key = request.headers.get(API_KEY_HEADER, "")
    if not key or len(key) > 256:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key requerida",
                            headers={"WWW-Authenticate": "ApiKey"})
    digest = hash_api_key(key)
    # Comparación en tiempo constante contra todos los hashes.
    matched = False
    for allowed in settings.api_key_hashes:
        matched |= hmac.compare_digest(digest, allowed)
    if not matched:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key inválida",
                            headers={"WWW-Authenticate": "ApiKey"})
    return digest[:12]


class RateLimiter:
    """Ventana deslizante en memoria. Para varios workers/instancias use un proxy o Redis."""

    def __init__(self, limit: int, window: float = 60.0):
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        if self.limit <= 0:
            return
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                retry = int(self.window - (now - hits[0])) + 1
                raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                    "Demasiadas solicitudes, intente más tarde",
                                    headers={"Retry-After": str(retry)})
            hits.append(now)
            if len(self._hits) > 10_000:  # evita crecimiento ilimitado de memoria
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]:
                    del self._hits[k]


CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, hsts: bool):
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        is_docs = path.startswith("/docs") or path.startswith("/redoc")

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"server"]
                extra = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
                    b"cross-origin-opener-policy": b"same-origin",
                    b"cross-origin-resource-policy": b"same-origin",
                    b"content-security-policy": (DOCS_CSP if is_docs else CSP).encode(),
                }
                if path.startswith("/api/"):
                    extra[b"cache-control"] = b"no-store"
                if self.hsts:
                    extra[b"strict-transport-security"] = b"max-age=63072000; includeSubDomains"
                existing = {k.lower() for k, _ in headers}
                headers += [(k, v) for k, v in extra.items() if k not in existing]
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class BodySizeLimitMiddleware:
    """Rechaza cuerpos mayores a ``max_bytes`` (413), tanto por Content-Length como en streaming."""

    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > self.max_bytes
                except ValueError:
                    too_big = True
                if too_big:
                    await self._reject(send)
                    return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(413,
                                        "El cuerpo de la solicitud es demasiado grande")
            return message

        await self.app(scope, limited_receive, send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"detail":"El cuerpo de la solicitud es demasiado grande"}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
