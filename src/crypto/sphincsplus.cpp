// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sphincsplus.h>
#include <crypto/sphincsplus/slh_dsa.h>

bool VerifySphincsSignature(std::span<const uint8_t> pubkey,
                            std::span<const uint8_t> signature,
                            const uint256& msg_hash)
{
    if (pubkey.size() != 32 || signature.size() != 4080) return false;

    // Use slh_verify_internal (no context string, matching BIP 369 usage)
    return slh_verify_internal(
        msg_hash.data(), msg_hash.size(),
        signature.data(), signature.size(),
        pubkey.data(),
        &slh_dsa_bitcoin) == 1;
}

int SphincsKeygen(uint8_t* sk, uint8_t* pk,
                  const uint8_t* sk_seed, const uint8_t* sk_prf,
                  const uint8_t* pk_seed)
{
    return slh_keygen_internal(sk, pk, sk_seed, sk_prf, pk_seed, &slh_dsa_bitcoin);
}

size_t SphincsSign(uint8_t* sig, const uint8_t* msg, size_t msg_len,
                   const uint8_t* sk)
{
    // Use deterministic signing (addrnd = NULL means use sk_prf)
    return slh_sign_internal(sig, msg, msg_len, sk, nullptr, &slh_dsa_bitcoin);
}
