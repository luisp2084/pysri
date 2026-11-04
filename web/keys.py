"""Genera una API key aleatoria y su hash SHA-256 para PYSRI_API_KEY_HASHES.

Uso: python -m web.keys
"""
import secrets

from web.security import hash_api_key


def main() -> None:
    key = secrets.token_urlsafe(32)
    print("API key (entréguela al cliente, no se vuelve a mostrar):")
    print(f"  {key}")
    print("Hash para PYSRI_API_KEY_HASHES:")
    print(f"  {hash_api_key(key)}")


if __name__ == "__main__":
    main()
