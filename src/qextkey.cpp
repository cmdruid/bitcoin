// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qextkey.h>

#include <base58.h>
#include <chainparams.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <support/cleanse.h>

#include <algorithm>
#include <cstring>

// --- QExtPubKey ---

void QExtPubKey::Encode(std::array<unsigned char, QI_EXTKEY_SIZE>& code) const
{
    extpub.Encode(code.data());
    std::memcpy(code.data() + BIP32_EXTKEY_SIZE, sphincs_pubkey.data(), 32);
}

void QExtPubKey::Decode(const std::array<unsigned char, QI_EXTKEY_SIZE>& code)
{
    extpub.Decode(code.data());
    std::memcpy(sphincs_pubkey.data(), code.data() + BIP32_EXTKEY_SIZE, 32);
}

bool QExtPubKey::Derive(QExtPubKey& out, unsigned int nChild) const
{
    if (!extpub.Derive(out.extpub, nChild)) {
        return false;
    }
    out.sphincs_pubkey = sphincs_pubkey;
    return true;
}

CTxDestination QExtPubKey::DeriveAddress(unsigned int child_index) const
{
    QExtPubKey child;
    if (!Derive(child, child_index)) {
        return CNoDestination{};
    }

    XOnlyPubKey child_xonly{child.extpub.pubkey};
    if (!child_xonly.IsFullyValid()) {
        return CNoDestination{};
    }

    // Build hybrid script: <sphincs_pk> OP_CHECKSPHINCSVERIFY OP_DROP <child_xonly> OP_CHECKSIG
    CScript hybrid_script;
    hybrid_script << std::span<const std::byte>{reinterpret_cast<const std::byte*>(sphincs_pubkey.data()), 32};
    hybrid_script << OP_CHECKSPHINCSVERIFY;
    hybrid_script << OP_DROP;
    hybrid_script << std::span<const std::byte>{reinterpret_cast<const std::byte*>(child_xonly.data()), 32};
    hybrid_script << OP_CHECKSIG;

    TaprootBuilder builder;
    builder.Add(0, hybrid_script, TAPROOT_LEAF_TAPSCRIPT);
    if (!builder.IsComplete()) {
        return CNoDestination{};
    }
    builder.Finalize(child_xonly);

    return WitnessV1Taproot{builder.GetOutput()};
}

// --- QExtKey ---

void QExtKey::Encode(std::array<unsigned char, QI_EXTKEY_SIZE>& code) const
{
    extkey.Encode(code.data());
    std::memcpy(code.data() + BIP32_EXTKEY_SIZE, sphincs_secret.data(), 64);
}

void QExtKey::Decode(const std::array<unsigned char, QI_EXTKEY_SIZE>& code)
{
    extkey.Decode(code.data());
    std::memcpy(sphincs_secret.data(), code.data() + BIP32_EXTKEY_SIZE, 64);
}

bool QExtKey::Derive(QExtKey& out, unsigned int nChild) const
{
    if (!extkey.Derive(out.extkey, nChild)) {
        return false;
    }
    out.sphincs_secret = sphincs_secret;
    return true;
}

QExtPubKey QExtKey::Neuter() const
{
    QExtPubKey ret;
    ret.extpub = extkey.Neuter();
    // SPHINCS+ public key is the last 32 bytes of the 64-byte secret key
    std::memcpy(ret.sphincs_pubkey.data(), sphincs_secret.data() + 32, 32);
    return ret;
}

// --- Base58check encode/decode ---

QExtPubKey DecodeQExtPubKey(const std::string& str)
{
    QExtPubKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, QExtPubKey::QI_EXTKEY_WITH_VERSION_SIZE)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(CChainParams::EXT_QI_PUBLIC_KEY);
        if (data.size() == QExtPubKey::QI_EXTKEY_SIZE + prefix.size() &&
            std::equal(prefix.begin(), prefix.end(), data.begin())) {
            std::array<unsigned char, QExtPubKey::QI_EXTKEY_SIZE> buf;
            std::memcpy(buf.data(), data.data() + prefix.size(), QExtPubKey::QI_EXTKEY_SIZE);
            key.Decode(buf);
        }
    }
    return key;
}

std::string EncodeQExtPubKey(const QExtPubKey& key)
{
    std::array<unsigned char, QExtPubKey::QI_EXTKEY_SIZE> buf{};
    key.Encode(buf);
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_QI_PUBLIC_KEY);
    data.insert(data.end(), buf.begin(), buf.end());
    return EncodeBase58Check(data);
}

QExtKey DecodeQExtKey(const std::string& str)
{
    QExtKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, QExtKey::QI_EXTKEY_WITH_VERSION_SIZE)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(CChainParams::EXT_QI_SECRET_KEY);
        if (data.size() == QExtKey::QI_EXTKEY_SIZE + prefix.size() &&
            std::equal(prefix.begin(), prefix.end(), data.begin())) {
            std::array<unsigned char, QExtKey::QI_EXTKEY_SIZE> buf;
            std::memcpy(buf.data(), data.data() + prefix.size(), QExtKey::QI_EXTKEY_SIZE);
            key.Decode(buf);
        }
    }
    if (!data.empty()) {
        memory_cleanse(data.data(), data.size());
    }
    return key;
}

std::string EncodeQExtKey(const QExtKey& key)
{
    std::array<unsigned char, QExtKey::QI_EXTKEY_SIZE> buf{};
    key.Encode(buf);
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_QI_SECRET_KEY);
    data.insert(data.end(), buf.begin(), buf.end());
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(buf.data(), buf.size());
    memory_cleanse(data.data(), data.size());
    return ret;
}
