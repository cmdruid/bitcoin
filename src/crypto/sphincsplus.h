// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SPHINCSPLUS_H
#define BITCOIN_CRYPTO_SPHINCSPLUS_H

#include <uint256.h>

#include <cstdint>
#include <span>

/** Verify a SPHINCS+ signature using BIP 369 bitcoin-optimized parameters.
 *
 * Uses standard SLH-DSA (FIPS 205) algorithms with custom tree parameters
 * (n=16, h=32, d=4, w=256, k=10, a=14). Signature size: 4080 bytes.
 *
 * @param pubkey    32-byte SPHINCS+ public key (PKseed || PKroot)
 * @param signature 4080-byte SLH-DSA signature
 * @param msg_hash  32-byte message hash (SPHINCS+ sighash from BIP 369)
 * @return true if the signature is valid
 */
bool VerifySphincsSignature(std::span<const uint8_t> pubkey,
                            std::span<const uint8_t> signature,
                            const uint256& msg_hash);

/** Generate an SLH-DSA key pair using BIP 369 bitcoin-optimized parameters.
 *
 * @param[out] sk   Secret key (output, 4*n = 64 bytes)
 * @param[out] pk   Public key (output, 2*n = 32 bytes)
 * @param sk_seed   Secret key seed (n = 16 bytes)
 * @param sk_prf    PRF key (n = 16 bytes)
 * @param pk_seed   Public key seed (n = 16 bytes)
 * @return 0 on success
 */
int SphincsKeygen(uint8_t* sk, uint8_t* pk,
                  const uint8_t* sk_seed, const uint8_t* sk_prf,
                  const uint8_t* pk_seed);

/** Sign a message using SLH-DSA with BIP 369 bitcoin-optimized parameters.
 *
 * @param[out] sig  Signature output buffer (must be >= 4080 bytes)
 * @param msg       Message to sign
 * @param msg_len   Length of message
 * @param sk        Secret key (4*n = 64 bytes)
 * @return Signature size (4080) on success, 0 on failure
 */
size_t SphincsSign(uint8_t* sig, const uint8_t* msg, size_t msg_len,
                   const uint8_t* sk);

#endif // BITCOIN_CRYPTO_SPHINCSPLUS_H
