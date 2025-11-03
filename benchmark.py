#!/usr/bin/env python3
"""Benchmark script for pyaegis - AEGIS authenticated encryption."""

import sys
import time

from pyaegis import (
    AEGIS128L,
    AEGIS128X2,
    AEGIS128X4,
    AEGIS256,
    AEGIS256X2,
    AEGIS256X4,
)


def format_throughput(bytes_processed, elapsed_time):
    """Format throughput in MB/s or GB/s."""
    mb_per_sec = (bytes_processed / (1024 * 1024)) / elapsed_time
    if mb_per_sec >= 1024:
        return f"{mb_per_sec / 1024:.2f} GB/s"
    return f"{mb_per_sec:.2f} MB/s"


def benchmark_variant(cipher, variant_name, message_sizes, iterations=1000):
    """Benchmark a specific AEGIS variant."""
    print(f"\n{'=' * 70}")
    print(f"Benchmarking {variant_name}")
    print(f"{'=' * 70}")

    key = cipher.random_key()
    nonce = cipher.random_nonce()

    results = []

    for size in message_sizes:
        message = b"x" * size

        # Warm-up
        for _ in range(10):
            cipher.encrypt(key, nonce, message)

        # Encryption benchmark
        start = time.perf_counter()
        for _ in range(iterations):
            ciphertext = cipher.encrypt(key, nonce, message)
        elapsed = time.perf_counter() - start

        enc_throughput = format_throughput(size * iterations, elapsed)

        # Decryption benchmark
        start = time.perf_counter()
        for _ in range(iterations):
            _ = cipher.decrypt(key, nonce, ciphertext)
        elapsed = time.perf_counter() - start

        dec_throughput = format_throughput(size * iterations, elapsed)

        # Detached mode benchmark (if supported)
        try:
            start = time.perf_counter()
            for _ in range(iterations):
                ct, tag = cipher.encrypt_detached(key, nonce, message)
            elapsed = time.perf_counter() - start
            enc_detached_throughput = format_throughput(size * iterations, elapsed)

            start = time.perf_counter()
            for _ in range(iterations):
                _ = cipher.decrypt_detached(key, nonce, ct, tag)
            elapsed = time.perf_counter() - start
            dec_detached_throughput = format_throughput(size * iterations, elapsed)
        except AttributeError:
            enc_detached_throughput = "N/A"
            dec_detached_throughput = "N/A"

        results.append(
            {
                "size": size,
                "enc": enc_throughput,
                "dec": dec_throughput,
                "enc_det": enc_detached_throughput,
                "dec_det": dec_detached_throughput,
            }
        )

    # Print results table
    print(
        f"\n{'Message Size':<15} {'Encrypt':<15} {'Decrypt':<15} {'Enc (detached)':<15} {'Dec (detached)':<15}"
    )
    print("-" * 75)

    for r in results:
        size_str = format_size(r["size"])
        print(f"{size_str:<15} {r['enc']:<15} {r['dec']:<15} {r['enc_det']:<15} {r['dec_det']:<15}")


def format_size(size):
    """Format size in human-readable format."""
    if size >= 1024 * 1024:
        return f"{size // (1024 * 1024)} MB"
    elif size >= 1024:
        return f"{size // 1024} KB"
    else:
        return f"{size} B"


def run_all_benchmarks():
    """Run benchmarks for all AEGIS variants."""
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "PyAEGIS Performance Benchmark" + " " * 24 + "║")
    print("╚" + "═" * 68 + "╝")

    # Message sizes to test
    small_sizes = [64, 256, 1024]  # More iterations for small messages
    medium_sizes = [8 * 1024, 64 * 1024]  # Medium iterations
    large_sizes = [1024 * 1024]  # Fewer iterations for large messages

    variants = [
        (
            AEGIS128L(),
            "AEGIS-128L",
            small_sizes + medium_sizes + large_sizes,
            [1000, 1000, 1000, 500, 100, 50],
        ),
        (
            AEGIS256(),
            "AEGIS-256",
            small_sizes + medium_sizes + large_sizes,
            [1000, 1000, 1000, 500, 100, 50],
        ),
        (
            AEGIS128X2(),
            "AEGIS-128X2",
            small_sizes + medium_sizes + large_sizes,
            [1000, 1000, 1000, 500, 100, 50],
        ),
        (
            AEGIS128X4(),
            "AEGIS-128X4",
            small_sizes + medium_sizes + large_sizes,
            [1000, 1000, 1000, 500, 100, 50],
        ),
        (
            AEGIS256X2(),
            "AEGIS-256X2",
            small_sizes + medium_sizes + large_sizes,
            [1000, 1000, 1000, 500, 100, 50],
        ),
        (
            AEGIS256X4(),
            "AEGIS-256X4",
            small_sizes + medium_sizes + large_sizes,
            [1000, 1000, 1000, 500, 100, 50],
        ),
    ]

    for cipher, name, sizes, iterations_list in variants:
        # Run benchmark with varying iterations based on message size
        print(f"\n{'=' * 70}")
        print(f"Benchmarking {name}")
        print(f"{'=' * 70}")

        key = cipher.random_key()
        nonce = cipher.random_nonce()

        results = []

        for size, iters in zip(sizes, iterations_list, strict=True):
            message = b"x" * size

            # Warm-up
            for _ in range(min(10, iters)):
                cipher.encrypt(key, nonce, message)

            # Encryption benchmark
            start = time.perf_counter()
            for _ in range(iters):
                ciphertext = cipher.encrypt(key, nonce, message)
            elapsed = time.perf_counter() - start

            enc_throughput = format_throughput(size * iters, elapsed)

            # Decryption benchmark
            start = time.perf_counter()
            for _ in range(iters):
                _ = cipher.decrypt(key, nonce, ciphertext)
            elapsed = time.perf_counter() - start

            dec_throughput = format_throughput(size * iters, elapsed)

            # Detached mode benchmark (if supported)
            if hasattr(cipher, "encrypt_detached") and hasattr(cipher, "decrypt_detached"):
                start = time.perf_counter()
                for _ in range(iters):
                    ct, tag = cipher.encrypt_detached(key, nonce, message)
                elapsed = time.perf_counter() - start
                enc_detached_throughput = format_throughput(size * iters, elapsed)

                start = time.perf_counter()
                for _ in range(iters):
                    _ = cipher.decrypt_detached(key, nonce, ct, tag)
                elapsed = time.perf_counter() - start
                dec_detached_throughput = format_throughput(size * iters, elapsed)
            else:
                enc_detached_throughput = "N/A"
                dec_detached_throughput = "N/A"

            results.append(
                {
                    "size": size,
                    "iters": iters,
                    "enc": enc_throughput,
                    "dec": dec_throughput,
                    "enc_det": enc_detached_throughput,
                    "dec_det": dec_detached_throughput,
                }
            )

        # Print results table
        print(
            f"\n{'Message Size':<15} {'Iterations':<12} {'Encrypt':<15} {'Decrypt':<15} {'Enc (det)':<15} {'Dec (det)':<15}"
        )
        print("-" * 97)

        for r in results:
            size_str = format_size(r["size"])
            print(
                f"{size_str:<15} {r['iters']:<12} {r['enc']:<15} {r['dec']:<15} {r['enc_det']:<15} {r['dec_det']:<15}"
            )

    print("\n" + "=" * 70)
    print("Benchmark complete!")
    print("=" * 70)
    print("\nNotes:")
    print("  - Higher throughput = better performance")
    print("  - X2/X4 variants use multi-lane SIMD for higher throughput")
    print("  - Performance depends on CPU features (AES-NI, AVX2, AVX-512, NEON)")
    print("  - Results may vary based on system load and CPU frequency scaling")


if __name__ == "__main__":
    try:
        run_all_benchmarks()
    except KeyboardInterrupt:
        print("\n\nBenchmark interrupted by user.")
        sys.exit(1)
