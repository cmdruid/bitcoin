# BIP 369 Status Report

**Date:** 2026-04-02 (updated)
**Branch:** `feat/bip-0361-draft`
**Status:** Proof-of-concept complete with comprehensive test coverage. BIP specification near review-ready.

## Summary

BIP 369 adds post-quantum SPHINCS+ signature verification to Tapscript by redefining OP_NOP4 (0xB3) as OP_CHECKSPHINCSVERIFY. The PoC reference implementation is functional: real SLH-DSA signatures are verified end-to-end in Bitcoin Core's consensus engine.

A companion BIP 368 (Quantum-Resistant Key-Path Hardening for Taproot) has been drafted but not yet implemented.

## Implementation Status

### Complete

| Component | Status | Notes |
|-----------|--------|-------|
| OP_CHECKSPHINCSVERIFY opcode handler | Done | NOP4 redefinition, CLTV/CSV pattern |
| Annex parsing (type 0x01, cursor) | Done | Strict format validation, cursor management |
| SignatureHashSphincs | Done | BIP 342 sighash minus sha_annex, spend_type=0x03 |
| SLH-DSA verification library | Done | Vendored slhdsa-c with custom Bitcoin params |
| Custom parameter set (slh_dsa_bitcoin) | Done | n=16, h=32, d=4, w=256, k=10, a=14 |
| Error codes (5 SPHINCS+-specific) | Done | Missing annex, bad format, no sig, verify fail, unconsumed |
| BIP 9 buried deployment activation | Done | -testactivationheight=sphincs@N |
| Dynamic mempool flag management | Done | DeploymentActiveAfter check |
| Deployment info RPC | Done | getdeploymentinfo includes "sphincs" |
| sphincs_signer CMake build target | Done | Proper build system integration |
| Python test framework (sphincs.py) | Done | Real keygen/signing via signer subprocess |
| Test vectors | Done | 7 vector sections in bip-0369-test-vectors.json |
| BIP pseudocode | Done | Annex parsing, opcode execution, unconsumed check |
| BIP resource limits section | Done | Weight budget, annex limits, max sigs analysis |
| BIP deployment section | Done | BIP 9, speedy trial, pre-activation usage |
| BIP wallet constructions | Done | NUMS + separate leaves, combined hybrid |
| BIP addendum (standard vs W+C_P+FP) | Done | Design rationale with size comparison |

### Not yet implemented

| Component | Notes |
|-----------|-------|
| BIP 368 (key-path hardening) | Drafted as spec, no code |
| W+C_P+FP optimization (3408-byte sigs) | Deferred; current uses standard FIPS 205 (4080 bytes) |
| Benchmarking | VALIDATION_WEIGHT_PER_SPHINCS_SIGOP is placeholder (50) |
| SHA-256 replacement (CSHA256) | Using vendored SHA-256, not Core's optimized version |
| Fuzz tests | No fuzz coverage yet |
| Wallet support | No key management, address generation, or tx construction |

## Test Coverage

### 26 functional tests across 11 sections

| Section | Tests | Coverage |
|---------|-------|---------|
| 1. Success cases | 5 | Hybrid, SPHINCS+-only, multi-sig, MAST 2-of-3 (2 paths) |
| 2. Invalid signatures | 2 | Corrupted sig, wrong pubkey |
| 3. Hybrid security | 2 | Invalid Schnorr + valid SPHINCS+, valid Schnorr + invalid SPHINCS+ |
| 4. Annex edge cases | 5 | Missing, bad type, trailing data, short annex, unconsumed |
| 5. Unknown key types | 2 | 31-byte pk, 33-byte pk |
| 6. Conditional branches | 2 | Unexecuted branch (no cursor advance), executed branch |
| 7. Block validation | 2 | Valid tx mined, invalid tx rejected |
| 8. Stack edge cases | 2 | Empty stack, cursor exceeds count |
| 9. OP_CODESEPARATOR | 2 | Correct codesep_pos, wrong codesep_pos |
| 10. Sigops budget | 1 | 3 sigs within budget |
| 11. Activation | 3 | Deployment info, NOP4 rejection pre-activation, SPHINCS+ enforcement post-activation |

### Unit tests

All existing script_tests and transaction_tests pass with no regressions.

## BIP Document Status

### BIP 369 (`dev/docs/bip-0369.mediawiki`)

| Section | Status |
|---------|--------|
| Abstract, Motivation | Complete |
| Design (hybrid migration, signing order, k-of-n) | Complete |
| Pre-activation usage ("quantum insurance") | Complete |
| Recommended wallet constructions | Complete (NUMS + separate leaves, combined hybrid) |
| Soft-fork compatibility | Complete |
| Specification (opcode, annex, cursor, sighash) | Complete with pseudocode |
| SPHINCS+ parameters (hypertree, WOTS+, FORS) | Complete |
| Backward compatibility | Complete |
| Deployment (BIP 9, speedy trial, activation semantics) | Complete |
| Resource limits | Complete |
| Security considerations (7 subsections) | Complete |
| Test vectors | Complete (7 vector sections) |
| Reference implementation | Complete |
| Addendum (standard vs W+C_P+FP rationale) | Complete |

### BIP 368 (`dev/docs/bip-0368.mediawiki`)

| Section | Status |
|---------|--------|
| Specification (annex type 0x02, NUMS ban, bare-key rules) | Complete |
| Deployment | Complete (TBD parameters) |
| Security considerations | Complete |
| Reference implementation | Not started |

## Commit History

| Commit | Description |
|--------|-------------|
| a05a939 | Phase 1: Script interpreter skeleton |
| 2cb665f | Phase 2: Python test framework |
| 0529d8a | Phase 3: SPHINCS+ crypto library |
| aa4e12f | Phase 4: Real signatures in functional tests |
| 74a4100 | BIP update: standard SLH-DSA (4080-byte sigs) |
| 15676b9 | BIP: deployment, pre-activation usage, wallet constructions |
| 97b39f7 | BIP: key-path quantum protection (later split to BIP 368) |
| fb8bee6 | Split key-path hardening into BIP 368 |
| 85a301b | BIP 368: invalid annex must fail |
| 298d1a3 | Fix: correct error code for malformed annex |
| 85181c9 | Test: comprehensive coverage (18 tests) |
| 40d26e5 | Test: stack, codeseparator, sigops (23 tests) |
| cff23d7 | Activation: BIP 9 buried deployment |
| 83eaa23 | Build: sphincs_signer CMake target |
| abdc7af | Doc: test vectors |
| bba14cc | Doc: pseudocode and resource limits |
| (this)  | Doc: updated status report |

## Remaining Follow-up Tasks

| # | Task | Priority | Effort |
|---|------|----------|--------|
| 5 | Benchmark SPHINCS+ verification cost | Medium-term | 2 hrs |
| 7 | Replace SHA-256 with Bitcoin Core's CSHA256 | Medium-term | 3-4 hrs |
| 8 | Add fuzz tests | Medium-term | 2-3 hrs |
| 10 | Implement BIP 368 | Long-term | Large |
| 11 | Wallet support | Long-term | Large |
| 12 | Security audit | Long-term | External |
| 13 | Community review / mailing list | Long-term | External |
