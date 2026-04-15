// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QEXTKEY_H
#define BITCOIN_QEXTKEY_H

#include <addresstype.h>
#include <key.h>
#include <pubkey.h>

#include <array>
#include <cstdint>
#include <string>

/** Quantum-insured extended public key (BIP 395).
 *
 * Extends the BIP 32 CExtPubKey with a 32-byte SPHINCS+ public key.
 * The SPHINCS+ key is constant across all child derivations (only the
 * secp256k1 key varies per BIP 32 child index).
 *
 * Payload: 74 bytes (BIP32) + 32 bytes (SPHINCS+) = 106 bytes.
 * With 4-byte version prefix: 110 bytes total.
 */
struct QExtPubKey {
    static constexpr size_t QI_EXTKEY_SIZE = BIP32_EXTKEY_SIZE + 32;            // 106
    static constexpr size_t QI_EXTKEY_WITH_VERSION_SIZE = QI_EXTKEY_SIZE + 4;   // 110

    CExtPubKey extpub;                            //!< Standard BIP32 extended public key
    std::array<unsigned char, 32> sphincs_pubkey{}; //!< SPHINCS+ public key (pk_seed || pk_root)

    void Encode(std::array<unsigned char, QI_EXTKEY_SIZE>& code) const;
    void Decode(const std::array<unsigned char, QI_EXTKEY_SIZE>& code);

    //! BIP 32 child derivation. SPHINCS+ key is carried unchanged.
    [[nodiscard]] bool Derive(QExtPubKey& out, unsigned int nChild) const;

    /** Derive a quantum-insured Taproot address at child index.
     *
     * Construction per BIP 395:
     *   Internal key: child_xonly (BIP 32 derived)
     *   Leaf A: <sphincs_pk> OP_CHECKSPHINCSVERIFY OP_DROP <child_xonly> OP_CHECKSIG
     */
    CTxDestination DeriveAddress(unsigned int child_index) const;

    friend bool operator==(const QExtPubKey& a, const QExtPubKey& b)
    {
        return a.extpub == b.extpub && a.sphincs_pubkey == b.sphincs_pubkey;
    }
};

/** Quantum-insured extended private key (BIP 395).
 *
 * Extends the BIP 32 CExtKey with a 64-byte SPHINCS+ secret key.
 *
 * Payload: 74 bytes (BIP32) + 64 bytes (SPHINCS+) = 138 bytes.
 * With 4-byte version prefix: 142 bytes total.
 */
struct QExtKey {
    static constexpr size_t QI_EXTKEY_SIZE = BIP32_EXTKEY_SIZE + 64;            // 138
    static constexpr size_t QI_EXTKEY_WITH_VERSION_SIZE = QI_EXTKEY_SIZE + 4;   // 142

    CExtKey extkey;                                //!< Standard BIP32 extended private key
    std::array<unsigned char, 64> sphincs_secret{}; //!< SPHINCS+ secret key

    void Encode(std::array<unsigned char, QI_EXTKEY_SIZE>& code) const;
    void Decode(const std::array<unsigned char, QI_EXTKEY_SIZE>& code);

    //! BIP 32 child derivation. SPHINCS+ key is carried unchanged.
    [[nodiscard]] bool Derive(QExtKey& out, unsigned int nChild) const;

    //! Get the public component (BIP32 neutered + SPHINCS+ pubkey).
    QExtPubKey Neuter() const;

    friend bool operator==(const QExtKey& a, const QExtKey& b)
    {
        return a.extkey == b.extkey && a.sphincs_secret == b.sphincs_secret;
    }
};

// Base58check encode/decode for quantum-insured extended keys
QExtPubKey DecodeQExtPubKey(const std::string& str);
std::string EncodeQExtPubKey(const QExtPubKey& key);
QExtKey DecodeQExtKey(const std::string& str);
std::string EncodeQExtKey(const QExtKey& key);

#endif // BITCOIN_QEXTKEY_H
