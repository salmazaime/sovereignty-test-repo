# app/auth/api_keys.py
"""
API key generation and hashing. Deliberately uses SHA-256, NOT
bcrypt -- worth being able to justify precisely, since using the
"more secure-sounding" algorithm here would actually be the wrong
call. An API key is a 256-bit cryptographically random secret, not a
human-chosen password -- it has no dictionary to attack and is
computationally infeasible to brute-force regardless of hash speed.
Bcrypt's deliberate slowness would only add needless latency to
EVERY authenticated machine request for zero additional security
benefit. Right tool for the actual threat model, not the reflexively
"stronger" one.
"""

import hashlib
import secrets

API_KEY_PREFIX = "svk"  # "sovereignty key" -- aids identification in logs and leak-scanning tools


def generate_api_key() -> tuple[str, str]:
    """
    Returns (plaintext_key, sha256_hash_hex). The plaintext is shown
    to the caller EXACTLY ONCE, at creation time, and is never stored
    anywhere -- only its hash is persisted. This mirrors how you'd
    never store a plaintext password; the same principle applies to
    any long-lived secret credential.
    """
    plaintext = f"{API_KEY_PREFIX}_{secrets.token_urlsafe(32)}"
    return plaintext, hash_api_key(plaintext)


def hash_api_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    