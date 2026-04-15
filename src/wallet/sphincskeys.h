// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_SPHINCSKEYS_H
#define BITCOIN_WALLET_SPHINCSKEYS_H

#include <key.h>
#include <support/allocators/secure.h>
#include <wallet/crypter.h>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

struct CExtKey;

namespace wallet {

/** An encapsulated SPHINCS+ (SLH-DSA) key pair for BIP 369 quantum-insured wallets.
 *
 * Secret key material uses secure_unique_ptr which:
 * - Allocates from locked (non-swappable) memory pages
 * - Clears memory on deallocation via memory_cleanse()
 * - Move semantics transfer ownership without copying
 * - Copy constructor explicitly clones into new secure allocation
 *
 * Secret key: 64 bytes (sk_seed || sk_prf || pk_seed || pk_root)
 * Public key: 32 bytes (pk_seed || pk_root)
 * Signature:  4080 bytes
 */
class SphincsKey
{
public:
    static constexpr size_t SECRET_SIZE = 64;
    static constexpr size_t PUBLIC_SIZE = 32;
    static constexpr size_t SIGNATURE_SIZE = 4080;
    static constexpr size_t SEED_COMPONENT_SIZE = 16; // n = 16 bytes per FIPS 205

    SphincsKey() noexcept = default;
    SphincsKey(SphincsKey&&) noexcept = default;
    SphincsKey& operator=(SphincsKey&&) noexcept = default;

    SphincsKey(const SphincsKey& other)
    {
        if (other.m_keydata) {
            MakeKeyData();
            *m_keydata = *other.m_keydata;
            m_pubkey = other.m_pubkey;
            m_valid = other.m_valid;
        }
    }

    SphincsKey& operator=(const SphincsKey& other)
    {
        if (this != &other) {
            m_valid = false; // Invalidate first to avoid transient valid state
            if (other.m_keydata) {
                MakeKeyData();
                *m_keydata = *other.m_keydata;
                m_pubkey = other.m_pubkey;
                m_valid = other.m_valid; // Restore after data is fully copied
            } else {
                ClearKeyData();
                m_pubkey = {};
            }
        }
        return *this;
    }

    /** Generate a key pair from three 16-byte seed components.
     *  Calls SphincsKeygen() from crypto/sphincsplus.h.
     */
    void Generate(const unsigned char* sk_seed,
                  const unsigned char* sk_prf,
                  const unsigned char* pk_seed);

    /** Derive a SPHINCS+ key from a BIP 32 master extended private key and account path.
     *
     *  Uses HMAC-SHA512("Sphincs seed", key || chaincode || account_path_bytes)
     *  and splits the first 48 bytes into three 16-byte seed components.
     *
     *  @param master_key   The BIP 32 master extended private key (CExtKey)
     *  @param account_path Account derivation path as uint32_t indices
     *                      (e.g., {0x8000018B, 0x80000000, 0x80000000} for m/395'/0'/0')
     */
    static SphincsKey DeriveFromMaster(const CExtKey& master_key,
                                       const std::vector<uint32_t>& account_path);

    /** Sign a 32-byte message hash.
     *  @param[in]  msg_hash  32-byte hash to sign
     *  @param[out] sig       Output signature (resized to SIGNATURE_SIZE = 4080 bytes)
     *  @return true on success
     */
    bool Sign(const uint256& msg_hash, std::vector<unsigned char>& sig) const;

    //! Check if the key is valid (has been generated or loaded).
    bool IsValid() const { return m_valid && m_keydata; }

    //! Raw pointer to the 64-byte secret key (secure memory).
    const unsigned char* SecretData() const { return m_keydata ? m_keydata->data() : nullptr; }

    //! Raw pointer to the 32-byte public key.
    const unsigned char* PubkeyData() const { return m_pubkey.data(); }

    //! Public key as a span.
    std::span<const unsigned char> PubkeySpan() const { return m_pubkey; }

    //! Secret key as CKeyingMaterial for use with EncryptSecret().
    CKeyingMaterial GetSecret() const;

    /** Load a key from raw secret bytes, verifying against expected public key.
     *  @param secret          64-byte secret key
     *  @param expected_pubkey 32-byte expected public key (integrity check)
     *  @return true if the secret key produces the expected public key
     */
    bool Load(std::span<const unsigned char> secret,
              std::span<const unsigned char> expected_pubkey);

private:
    //! 64-byte secret key in secure (locked, wiped) memory.
    secure_unique_ptr<std::array<unsigned char, SECRET_SIZE>> m_keydata;

    //! 32-byte public key.
    std::array<unsigned char, PUBLIC_SIZE> m_pubkey{};

    //! Whether this key has been successfully generated or loaded.
    bool m_valid{false};

    void MakeKeyData()
    {
        if (!m_keydata) m_keydata = make_secure_unique<std::array<unsigned char, SECRET_SIZE>>();
    }

    void ClearKeyData()
    {
        m_keydata.reset();
        m_valid = false;
    }
};

} // namespace wallet

#endif // BITCOIN_WALLET_SPHINCSKEYS_H
