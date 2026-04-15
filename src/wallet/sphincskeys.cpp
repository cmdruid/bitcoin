// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/sphincskeys.h>

#include <crypto/common.h>
#include <crypto/hmac_sha512.h>
#include <crypto/sphincsplus.h>
#include <key.h>

#include <cstring>

namespace wallet {

void SphincsKey::Generate(const unsigned char* sk_seed,
                          const unsigned char* sk_prf,
                          const unsigned char* pk_seed)
{
    MakeKeyData();
    int ret = SphincsKeygen(m_keydata->data(), m_pubkey.data(),
                            sk_seed, sk_prf, pk_seed);
    m_valid = (ret == 0);
    if (!m_valid) {
        ClearKeyData();
    }
}

SphincsKey SphincsKey::DeriveFromMaster(const CExtKey& master_key,
                                         const std::vector<uint32_t>& account_path)
{
    // Serialize account path as BIP 32 encoding (4-byte big-endian per level)
    std::vector<unsigned char> path_bytes;
    path_bytes.reserve(account_path.size() * 4);
    for (uint32_t index : account_path) {
        unsigned char buf[4];
        WriteBE32(buf, index);
        path_bytes.insert(path_bytes.end(), buf, buf + 4);
    }

    // HMAC-SHA512("Sphincs seed", key || chaincode || path_bytes)
    // Key is exactly 12 bytes ("Sphincs seed" without null terminator).
    // This is consensus-critical: changing the key changes all derived SPHINCS+ keys.
    static constexpr char SPHINCS_HMAC_KEY[] = "Sphincs seed";
    static constexpr size_t SPHINCS_HMAC_KEY_LEN = 12;
    static_assert(sizeof(SPHINCS_HMAC_KEY) - 1 == SPHINCS_HMAC_KEY_LEN,
                  "HMAC key must be exactly 12 bytes");
    std::vector<unsigned char, secure_allocator<unsigned char>> out(CHMAC_SHA512::OUTPUT_SIZE);

    CHMAC_SHA512{reinterpret_cast<const unsigned char*>(SPHINCS_HMAC_KEY), SPHINCS_HMAC_KEY_LEN}
        .Write(UCharCast(master_key.key.data()), 32)
        .Write(master_key.chaincode.data(), 32)
        .Write(path_bytes.data(), path_bytes.size())
        .Finalize(out.data());

    // Split first 48 bytes into three 16-byte seed components
    SphincsKey result;
    result.Generate(out.data(),                     // sk_seed: bytes 0-15
                    out.data() + SEED_COMPONENT_SIZE,   // sk_prf:  bytes 16-31
                    out.data() + SEED_COMPONENT_SIZE * 2); // pk_seed: bytes 32-47
    return result;
}

bool SphincsKey::Sign(const uint256& msg_hash, std::vector<unsigned char>& sig) const
{
    if (!IsValid()) return false;

    sig.resize(SIGNATURE_SIZE);
    size_t ret = SphincsSign(sig.data(),
                             msg_hash.data(), msg_hash.size(),
                             m_keydata->data());
    if (ret != SIGNATURE_SIZE) {
        sig.clear();
        return false;
    }
    return true;
}

CKeyingMaterial SphincsKey::GetSecret() const
{
    if (!IsValid()) return {};
    return CKeyingMaterial{m_keydata->begin(), m_keydata->end()};
}

// The SPHINCS+ public key is defined as the last 32 bytes of the 64-byte
// secret key (pk_seed || pk_root). Byte comparison is sufficient because
// any corruption of the first 32 bytes (sk_seed || sk_prf) would produce
// invalid signatures caught at consensus verification time.
bool SphincsKey::Load(std::span<const unsigned char> secret,
                      std::span<const unsigned char> expected_pubkey)
{
    if (secret.size() != SECRET_SIZE || expected_pubkey.size() != PUBLIC_SIZE) {
        return false;
    }

    MakeKeyData();
    std::memcpy(m_keydata->data(), secret.data(), SECRET_SIZE);

    // The public key is the last 32 bytes of the 64-byte secret key
    // (pk_seed || pk_root), which matches the public key format.
    std::memcpy(m_pubkey.data(), secret.data() + SECRET_SIZE - PUBLIC_SIZE, PUBLIC_SIZE);

    // Verify the derived public key matches the expected one
    if (std::memcmp(m_pubkey.data(), expected_pubkey.data(), PUBLIC_SIZE) != 0) {
        ClearKeyData();
        m_pubkey = {};
        return false;
    }

    // Cryptographic verification: sign and verify a fixed test message to
    // detect corruption of sk_seed/sk_prf (first 32 bytes of the secret key)
    // that byte comparison alone cannot catch.
    {
        static const uint256 test_msg{uint256::ONE};
        std::vector<unsigned char> test_sig(SIGNATURE_SIZE);
        size_t sig_len = SphincsSign(test_sig.data(), test_msg.data(), test_msg.size(), m_keydata->data());
        if (sig_len != SIGNATURE_SIZE ||
            !VerifySphincsSignature(m_pubkey, test_sig, test_msg)) {
            ClearKeyData();
            m_pubkey = {};
            return false;
        }
    }

    m_valid = true;
    return true;
}

} // namespace wallet
