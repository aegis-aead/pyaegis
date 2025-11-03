#!/usr/bin/env python3
"""Demo script showcasing pyaegis functionality."""

from pyaegis import AEGIS128L, AEGIS128L_MAC, AEGIS256, AEGIS256_MAC, DecryptionError


def demo_basic_encryption():
    """Demonstrate basic encryption and decryption."""
    print("=" * 60)
    print("Demo 1: Basic Encryption/Decryption with AEGIS-128L")
    print("=" * 60)

    cipher = AEGIS128L()
    key = cipher.random_key()
    nonce = cipher.random_nonce()

    plaintext = b"Hello, World! This is a secret message."
    print(f"Plaintext: {plaintext}")

    # Encrypt
    ciphertext = cipher.encrypt(key, nonce, plaintext)
    print(f"Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()[:60]}...")

    # Decrypt
    decrypted = cipher.decrypt(key, nonce, ciphertext)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {decrypted == plaintext}")
    print()


def demo_aad():
    """Demonstrate additional authenticated data."""
    print("=" * 60)
    print("Demo 2: Encryption with Additional Authenticated Data")
    print("=" * 60)

    cipher = AEGIS128L()
    key = cipher.random_key()
    nonce = cipher.random_nonce()

    plaintext = b"Secret payload"
    aad = b"Message ID: 12345, Timestamp: 2024-01-01"

    print(f"Plaintext: {plaintext}")
    print(f"AAD (authenticated but not encrypted): {aad}")

    # Encrypt with AAD
    ciphertext = cipher.encrypt(key, nonce, plaintext, associated_data=aad)

    # Decrypt with correct AAD
    decrypted = cipher.decrypt(key, nonce, ciphertext, associated_data=aad)
    print(f"Decrypted with correct AAD: {decrypted}")

    # Try to decrypt with wrong AAD (this will fail)
    try:
        wrong_aad = b"Wrong AAD"
        cipher.decrypt(key, nonce, ciphertext, associated_data=wrong_aad)
        print("ERROR: Should have failed with wrong AAD!")
    except DecryptionError:
        print("✓ Correctly rejected wrong AAD")
    print()


def demo_detached_tag():
    """Demonstrate detached tag mode."""
    print("=" * 60)
    print("Demo 3: Detached Tag Mode")
    print("=" * 60)

    cipher = AEGIS128L()
    key = cipher.random_key()
    nonce = cipher.random_nonce()

    plaintext = b"Message with detached tag"

    # Encrypt with detached tag
    ciphertext, tag = cipher.encrypt_detached(key, nonce, plaintext)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")
    print(f"Tag ({len(tag)} bytes): {tag.hex()}")

    # Decrypt with detached tag
    decrypted = cipher.decrypt_detached(key, nonce, ciphertext, tag)
    print(f"Decrypted: {decrypted}")
    print()


def demo_tag_sizes():
    """Demonstrate different tag sizes."""
    print("=" * 60)
    print("Demo 4: Different Tag Sizes")
    print("=" * 60)

    plaintext = b"Test message"
    key = AEGIS128L.random_key()
    nonce = AEGIS128L.random_nonce()

    # 32-byte tag (default, recommended)
    cipher32 = AEGIS128L(tag_size=32)
    ct32 = cipher32.encrypt(key, nonce, plaintext)
    print(f"With 32-byte tag: {len(ct32)} bytes total ({len(plaintext)} + 32)")

    # 16-byte tag
    cipher16 = AEGIS128L(tag_size=16)
    ct16 = cipher16.encrypt(key, nonce, plaintext)
    print(f"With 16-byte tag: {len(ct16)} bytes total ({len(plaintext)} + 16)")
    print()


def demo_aegis256():
    """Demonstrate AEGIS-256."""
    print("=" * 60)
    print("Demo 5: AEGIS-256 (256-bit security)")
    print("=" * 60)

    cipher = AEGIS256()
    key = cipher.random_key()
    nonce = cipher.random_nonce()

    print(f"Key size: {len(key)} bytes")
    print(f"Nonce size: {len(nonce)} bytes")

    plaintext = b"High security message"
    ciphertext = cipher.encrypt(key, nonce, plaintext)
    decrypted = cipher.decrypt(key, nonce, ciphertext)

    print(f"Plaintext: {plaintext}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {decrypted == plaintext}")
    print()


def demo_stream():
    """Demonstrate stream generation."""
    print("=" * 60)
    print("Demo 6: Pseudo-Random Stream Generation")
    print("=" * 60)

    key = AEGIS128L.random_key()
    nonce = AEGIS128L.random_nonce()

    # Generate deterministic stream
    stream1 = AEGIS128L.stream(key, nonce, 32)
    stream2 = AEGIS128L.stream(key, nonce, 32)

    print(f"Stream 1: {stream1.hex()}")
    print(f"Stream 2: {stream2.hex()}")
    print(f"Streams are identical (deterministic): {stream1 == stream2}")
    print()


def demo_tampering_detection():
    """Demonstrate tampering detection."""
    print("=" * 60)
    print("Demo 7: Tampering Detection")
    print("=" * 60)

    cipher = AEGIS128L()
    key = cipher.random_key()
    nonce = cipher.random_nonce()

    plaintext = b"Important message"
    ciphertext = cipher.encrypt(key, nonce, plaintext)

    # Tamper with the ciphertext
    tampered = bytearray(ciphertext)
    tampered[0] ^= 1  # Flip one bit

    print(f"Original ciphertext: {ciphertext.hex()[:40]}...")
    print(f"Tampered ciphertext: {bytes(tampered).hex()[:40]}...")

    try:
        cipher.decrypt(key, nonce, bytes(tampered))
        print("ERROR: Should have detected tampering!")
    except DecryptionError:
        print("✓ Tampering detected and rejected")
    print()


def demo_mac_basic():
    """Demonstrate basic MAC generation and verification."""
    print("=" * 60)
    print("Demo 8: MAC - Message Authentication Code")
    print("=" * 60)

    key = AEGIS128L_MAC.random_key()
    nonce = AEGIS128L_MAC.random_nonce()

    # Generate MAC
    mac = AEGIS128L_MAC(key, nonce)
    mac.update(b"This is ")
    mac.update(b"an authenticated ")
    mac.update(b"message")
    tag = mac.final()

    print(f"Message: This is an authenticated message")
    print(f"MAC tag ({len(tag)} bytes): {tag.hex()}")

    # Verify MAC with correct data
    mac_verify = AEGIS128L_MAC(key, nonce)
    mac_verify.update(b"This is an authenticated message")
    mac_verify.verify(tag)
    print("✓ MAC verification successful")

    # Try to verify with wrong data
    try:
        mac_wrong = AEGIS128L_MAC(key, nonce)
        mac_wrong.update(b"This is a tampered message")
        mac_wrong.verify(tag)
        print("ERROR: Should have failed with wrong data!")
    except DecryptionError:
        print("✓ Correctly rejected wrong data")
    print()


def demo_mac_use_cases():
    """Demonstrate MAC use cases."""
    print("=" * 60)
    print("Demo 9: MAC Use Cases")
    print("=" * 60)

    print("MAC provides authentication without encryption.")
    print("Use cases:")
    print("  - Authenticating public data")
    print("  - API request signatures")
    print("  - Data integrity verification")
    print("  - Message authentication in custom protocols")
    print()

    # Example: Authenticating a file
    key = AEGIS256_MAC.random_key()
    nonce = AEGIS256_MAC.random_nonce()

    file_data = b"Important file contents that must not be tampered with."

    mac = AEGIS256_MAC(key, nonce)
    mac.update(file_data)
    tag = mac.final()

    print(f"File size: {len(file_data)} bytes")
    print(f"MAC tag: {tag.hex()}")
    print()

    # Later, verify the file hasn't been tampered with
    mac_check = AEGIS256_MAC(key, nonce)
    mac_check.update(file_data)
    mac_check.verify(tag)
    print("✓ File integrity verified")
    print()


if __name__ == "__main__":
    print("\n🔐 PyAEGIS Demo - High-Performance Authenticated Encryption\n")

    demo_basic_encryption()
    demo_aad()
    demo_detached_tag()
    demo_tag_sizes()
    demo_aegis256()
    demo_stream()
    demo_tampering_detection()
    demo_mac_basic()
    demo_mac_use_cases()

    print("=" * 60)
    print("All demos completed successfully!")
    print("=" * 60)
