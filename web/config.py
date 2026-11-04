"""Configuración de la aplicación web desde variables de entorno."""
import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value else default


def _list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    env: str = "production"
    #: Hashes SHA-256 (hex) de las API keys autorizadas. Nunca guarde las claves en claro.
    api_key_hashes: frozenset[str] = field(default_factory=frozenset)
    #: Solo se respeta cuando env == "development".
    auth_disabled: bool = False
    #: Permite enviar comprobantes al ambiente de PRODUCCIÓN del SRI.
    allow_production: bool = False
    allowed_hosts: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1"])
    cors_origins: list[str] = field(default_factory=list)
    max_body_bytes: int = 1024 * 1024
    max_cert_bytes: int = 100 * 1024
    rate_limit_per_minute: int = 60
    sensitive_rate_limit_per_minute: int = 10
    sri_timeout: int = 30
    sri_verify_tls: bool = True
    sri_auth_attempts: int = 5
    sri_auth_delay: float = 3.0
    trust_proxy_headers: bool = False

    @property
    def is_development(self) -> bool:
        return self.env == "development"

    @property
    def auth_enabled(self) -> bool:
        return not (self.is_development and self.auth_disabled)

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            env=os.getenv("PYSRI_ENV", "production").strip().lower(),
            api_key_hashes=frozenset(h.lower() for h in _list("PYSRI_API_KEY_HASHES")),
            auth_disabled=_bool("PYSRI_AUTH_DISABLED", False),
            allow_production=_bool("PYSRI_ALLOW_PRODUCTION", False),
            allowed_hosts=_list("PYSRI_ALLOWED_HOSTS", "localhost,127.0.0.1"),
            cors_origins=_list("PYSRI_CORS_ORIGINS"),
            max_body_bytes=_int("PYSRI_MAX_BODY_BYTES", 1024 * 1024),
            max_cert_bytes=_int("PYSRI_MAX_CERT_BYTES", 100 * 1024),
            rate_limit_per_minute=_int("PYSRI_RATE_LIMIT_PER_MINUTE", 60),
            sensitive_rate_limit_per_minute=_int("PYSRI_SENSITIVE_RATE_LIMIT_PER_MINUTE", 10),
            sri_timeout=_int("PYSRI_SRI_TIMEOUT", 30),
            sri_verify_tls=_bool("PYSRI_SRI_VERIFY_TLS", True),
            sri_auth_attempts=_int("PYSRI_SRI_AUTH_ATTEMPTS", 5),
            sri_auth_delay=float(os.getenv("PYSRI_SRI_AUTH_DELAY", "3")),
            trust_proxy_headers=_bool("PYSRI_TRUST_PROXY_HEADERS", False),
        )

    def validate(self) -> None:
        if self.env not in {"production", "development"}:
            raise RuntimeError("PYSRI_ENV debe ser 'production' o 'development'")
        if self.auth_enabled and not self.api_key_hashes:
            raise RuntimeError(
                "Configure PYSRI_API_KEY_HASHES (genere una con: python -m web.keys). "
                "Solo en desarrollo puede usar PYSRI_AUTH_DISABLED=true."
            )
        for h in self.api_key_hashes:
            if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
                raise RuntimeError("PYSRI_API_KEY_HASHES debe contener hashes SHA-256 en hexadecimal")
        if not self.is_development and "*" in self.allowed_hosts:
            raise RuntimeError("PYSRI_ALLOWED_HOSTS no puede ser '*' en producción")
        if not self.is_development and "*" in self.cors_origins:
            raise RuntimeError("PYSRI_CORS_ORIGINS no puede ser '*' en producción")
