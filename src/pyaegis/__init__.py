"""
Python bindings for libaegis - high-performance AEGIS authenticated encryption.

This module provides Pythonic interfaces to the AEGIS family of authenticated
encryption algorithms (AEGIS-128L, AEGIS-256, and their multi-lane variants).

Basic usage:
    >>> from pyaegis import AEGIS128L
    >>> cipher = AEGIS128L()
    >>> key = cipher.random_key()
    >>> nonce = cipher.random_nonce()
    >>> plaintext = b"Hello, World!"
    >>> ciphertext = cipher.encrypt(key, nonce, plaintext)
    >>> decrypted = cipher.decrypt(key, nonce, ciphertext)
    >>> assert decrypted == plaintext
"""

from .aegis import (
    AEGIS128L,
    AEGIS128L_MAC,
    AEGIS128X2,
    AEGIS128X2_MAC,
    AEGIS128X4,
    AEGIS128X4_MAC,
    AEGIS256,
    AEGIS256_MAC,
    AEGIS256X2,
    AEGIS256X2_MAC,
    AEGIS256X4,
    AEGIS256X4_MAC,
    AEGISError,
    DecryptionError,
)

__version__ = "0.1.0"

__all__ = [
    "AEGIS128L",
    "AEGIS128L_MAC",
    "AEGIS128X2",
    "AEGIS128X2_MAC",
    "AEGIS128X4",
    "AEGIS128X4_MAC",
    "AEGIS256",
    "AEGIS256_MAC",
    "AEGIS256X2",
    "AEGIS256X2_MAC",
    "AEGIS256X4",
    "AEGIS256X4_MAC",
    "AEGISError",
    "DecryptionError",
]
