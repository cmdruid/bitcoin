#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""SPHINCS+ test utilities for BIP 369 functional tests.

Uses the sphincs_signer helper binary for real SLH-DSA keygen and signing.
"""

import os
import struct
import subprocess

SPHINCS_SIG_SIZE = 4080
SPHINCS_PK_SIZE = 32
SPHINCS_SK_SIZE = 64
SPHINCS_N = 16  # hash output size
SPHINCS_ANNEX_TYPE = 0x04


class SphincsSigner:
    """Manages a sphincs_signer subprocess for keygen and signing."""

    _instance = None

    @classmethod
    def get(cls):
        if cls._instance is None:
            # Find the signer binary relative to the test framework
            signer_path = os.path.join(
                os.path.dirname(__file__), '..', '..', '..', 'build', 'bin', 'sphincs_signer'
            )
            signer_path = os.path.normpath(signer_path)
            if not os.path.exists(signer_path):
                raise FileNotFoundError(f"sphincs_signer not found at {signer_path}")
            cls._instance = cls(signer_path)
        return cls._instance

    def __init__(self, signer_path):
        self.proc = subprocess.Popen(
            [signer_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def keygen(self, sk_seed, sk_prf, pk_seed):
        """Generate a key pair. Seeds are 16 bytes each."""
        assert len(sk_seed) == SPHINCS_N and len(sk_prf) == SPHINCS_N and len(pk_seed) == SPHINCS_N
        cmd = f"KEYGEN {sk_seed.hex()} {sk_prf.hex()} {pk_seed.hex()}\n"
        self.proc.stdin.write(cmd)
        self.proc.stdin.flush()
        line = self.proc.stdout.readline().strip()
        parts = line.split()
        assert parts[0] == "SK" and parts[2] == "PK", f"Unexpected keygen response: {line}"
        sk = bytes.fromhex(parts[1])
        pk = bytes.fromhex(parts[3])
        return sk, pk

    def sign(self, sk, msg):
        """Sign a message. sk is 64 bytes, msg is arbitrary bytes."""
        assert len(sk) == SPHINCS_SK_SIZE
        cmd = f"SIGN {sk.hex()} {msg.hex()}\n"
        self.proc.stdin.write(cmd)
        self.proc.stdin.flush()
        line = self.proc.stdout.readline().strip()
        parts = line.split()
        assert parts[0] == "SIG", f"Unexpected sign response: {line}"
        sig = bytes.fromhex(parts[1])
        assert len(sig) == SPHINCS_SIG_SIZE, f"Bad sig size: {len(sig)}"
        return sig

    def close(self):
        if self.proc:
            self.proc.stdin.write("QUIT\n")
            self.proc.stdin.flush()
            self.proc.wait()
            self.proc = None

    def __del__(self):
        self.close()


class SphincsKey:
    """SPHINCS+ key pair using real SLH-DSA keygen and signing."""

    def __init__(self, seed=b'\x01' * 16):
        """Create a key pair from a 16-byte seed.

        The seed is used as sk_seed. sk_prf and pk_seed are derived
        deterministically from the seed for testing purposes.
        """
        assert len(seed) == SPHINCS_N, f"Seed must be {SPHINCS_N} bytes, got {len(seed)}"
        signer = SphincsSigner.get()
        # Derive sk_prf and pk_seed deterministically from seed
        import hashlib
        sk_prf = hashlib.sha256(b'sphincs_sk_prf:' + seed).digest()[:SPHINCS_N]
        pk_seed = hashlib.sha256(b'sphincs_pk_seed:' + seed).digest()[:SPHINCS_N]
        self.sk, self.pubkey = signer.keygen(seed, sk_prf, pk_seed)

    def sign(self, msg):
        """Sign a message (typically a 32-byte sighash)."""
        signer = SphincsSigner.get()
        return signer.sign(self.sk, msg)


def build_sphincs_annex(signatures):
    """Build an annex carrying SPHINCS+ signatures.

    Format: 0x50 || 0x01 || compact_size(N) || sig_1 || ... || sig_N
    """
    n = len(signatures)
    # CompactSize encoding
    if n < 253:
        cs = bytes([n])
    elif n <= 0xffff:
        cs = b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        cs = b'\xfe' + struct.pack('<I', n)
    else:
        cs = b'\xff' + struct.pack('<Q', n)

    annex = bytes([0x50, SPHINCS_ANNEX_TYPE]) + cs
    for sig in signatures:
        assert len(sig) == SPHINCS_SIG_SIZE, f"Signature must be {SPHINCS_SIG_SIZE} bytes, got {len(sig)}"
        annex += sig
    return annex
