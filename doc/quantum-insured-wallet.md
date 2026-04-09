# Quantum-Insured Wallet (BIP 368/369)

## Overview

The quantum-insured wallet provides post-quantum security for Bitcoin Taproot
outputs using SPHINCS+ (SLH-DSA) signatures. Each address contains a hybrid
tapleaf that requires both Schnorr and SPHINCS+ signatures, providing defense
against quantum ECDLP attacks.

## Quick Start

```bash
# Create a wallet
bitcoin-cli createwallet "quantum"

# Create SPHINCS+ key and register QI descriptor
bitcoin-cli createsphincskey

# Generate a quantum-insured address
bitcoin-cli getquantumaddress

# Or equivalently (QI descriptor is active for bech32m):
bitcoin-cli getnewaddress "" bech32m
```

## RPCs

### `createsphincskey [account_index]`

Derives a SPHINCS+ keypair from the wallet's master key and registers a
quantum-insured Taproot descriptor. One SPHINCS+ key per account.

- Derivation: `HMAC-SHA512("Sphincs seed", master_ext_privkey || account_path)`
- Account path: `m/395'/coin_type'/account'`
- Registers both external (`/0/*`) and internal (`/1/*`) QI descriptors
- Returns: `sphincs_pubkey` (32 bytes hex), `qi_descriptor`

### `getquantumaddress`

Returns the next quantum-insured Taproot address from the active QI descriptor.
Equivalent to `getnewaddress "" bech32m` when a QI descriptor is registered.

### `listsphincskeys`

Lists all SPHINCS+ keys in the wallet with their public keys.

### `exportqpub`

Exports the quantum-insured extended public key (base58check `Q1...` string).
The qpub contains the BIP 32 xpub + SPHINCS+ public key, enabling watch-only
wallets to derive all QI addresses.

### `importqpub <qpub_string>`

Imports a qpub as a watch-only QI descriptor. The wallet will track incoming
payments to all addresses derived from the qpub but cannot spend.

### `exportqprv`

Exports the quantum-insured extended private key (base58check `Q1...` string).
Requires wallet to be unlocked. Contains both BIP 32 private key and SPHINCS+
secret key.

### `importqprv <qprv_string>`

Imports a qprv with full signing capability. Creates a QI descriptor that can
both track and spend quantum-insured outputs.

## Descriptor Syntax

Standard (recommended):
```
qr(qpub/0/*)
```

Advanced (manual tree construction):
```
tr(xpub/0/*, qis(SPHINCS_HEX, xpub/0/*))
```

The `qr()` descriptor accepts a `qpub` (quantum-insured extended public key)
and auto-constructs the hybrid SPHINCS+ tapleaf. It is a drop-in replacement
for `tr()` — same derivation paths, same address format.

Where:
- `xpub` is the account-level BIP 32 extended public key
- `SPHINCS_HEX` is the 32-byte SPHINCS+ public key (64 hex chars)
- `qis()` expands to: `<SPHINCS_HEX> OP_CHECKSPHINCSVERIFY OP_DROP <EC_KEY> OP_CHECKSIG`

## Spending Paths

### Normal operation (key-path)
- Schnorr signature for the output key (~64 bytes)
- Post-BIP 368: includes annex with internal key disclosure (~130 bytes total)
- Most efficient, hybrid tapleaf never revealed

### Post-quantum emergency (script-path)
- Hybrid tapleaf requires both SPHINCS+ and Schnorr signatures
- SPHINCS+ signature carried in annex (~4 KB)
- An attacker must break both Schnorr and SPHINCS+ simultaneously

## Key Derivation

- **Purpose**: `395'` (BIP 395)
- **SPHINCS+ derivation**: `HMAC-SHA512("Sphincs seed", CExtKey.key || CExtKey.chaincode || path_bytes)[:48]`
- **Seed split**: bytes 0-15 → sk_seed, 16-31 → sk_prf, 32-47 → pk_seed
- **Key sizes**: secret 64 bytes, public 32 bytes, signature 4080 bytes

## Extended Key Format

- **qpub**: 110 bytes (78 BIP32 + 32 SPHINCS+ pubkey), base58 prefix `Q1...`
- **qprv**: 142 bytes (78 BIP32 + 64 SPHINCS+ secret), base58 prefix `Q1...`
- **Testnet**: prefix `T4...`/`T5...`

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Schnorr P2TR verify | ~27 µs | Baseline |
| SPHINCS+ verify | ~1,756 µs | 64x Schnorr |
| SPHINCS+ sign | ~918 ms | Offline, doesn't affect block validation |
| QI address derivation | <1 ms | BIP 32 child key + TaprootBuilder |
| Key-path spend (with annex) | ~27 µs verify | +66 bytes witness |

SPHINCS+ signing is slow (~1 second) but only used for the emergency
script-path spend. Normal key-path spending has no SPHINCS+ overhead.

Validation weight: `VALIDATION_WEIGHT_PER_SPHINCS_SIGOP = 3200` (64x Schnorr's
50), ensuring SPHINCS+ transactions pay proportional block-space cost.

Run benchmarks: `build/bin/bench_bitcoin -filter="Sphincs"`

## Activation

BIP 369 (OP_CHECKSPHINCSVERIFY) requires BIP 368 (key-path hardening)
co-activation. Both must be active for SPHINCS+ verification to be enforced.
