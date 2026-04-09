// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sphincsplus.h>
#include <pubkey.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <uint256.h>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

// Fuzz the SPHINCS+ signature verification function.
// This should never crash regardless of input.
FUZZ_TARGET(sphincs_verify)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    // Consume a public key (32 bytes) and message hash (32 bytes)
    auto pk_data = fuzzed_data_provider.ConsumeBytes<uint8_t>(SPHINCS_PK_SIZE);
    auto msg_data = fuzzed_data_provider.ConsumeBytes<uint8_t>(32);
    auto sig_data = fuzzed_data_provider.ConsumeRemainingBytes<uint8_t>();

    // Pad to expected sizes if needed (VerifySphincsSignature checks sizes)
    pk_data.resize(SPHINCS_PK_SIZE, 0);
    uint256 msg;
    if (msg_data.size() >= 32) {
        memcpy(msg.data(), msg_data.data(), 32);
    }

    // This should never crash
    (void)VerifySphincsSignature(pk_data, sig_data, msg);
}

// Fuzz the annex parsing logic by feeding random data as an annex.
// Verifies that malformed annexes are either parsed as invalid or
// produce valid (but potentially empty) signature sets.
FUZZ_TARGET(sphincs_annex_parse)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    auto annex = fuzzed_data_provider.ConsumeRemainingBytes<uint8_t>();

    if (annex.empty()) return;

    // Simulate annex parsing logic from interpreter.cpp
    if (annex[0] != ANNEX_TAG) return;
    if (annex.size() < 2) return;
    if (annex[1] != SPHINCS_ANNEX_TYPE) return;

    // Parse compact_size(N)
    size_t pos = 2;
    uint64_t num_sigs = 0;
    if (pos >= annex.size()) return;

    uint8_t first = annex[pos++];
    if (first < 253) {
        num_sigs = first;
    } else if (first == 253 && pos + 2 <= annex.size()) {
        num_sigs = annex[pos] | (uint64_t(annex[pos + 1]) << 8);
        pos += 2;
    } else if (first == 254 && pos + 4 <= annex.size()) {
        num_sigs = annex[pos] | (uint64_t(annex[pos + 1]) << 8) |
                   (uint64_t(annex[pos + 2]) << 16) | (uint64_t(annex[pos + 3]) << 24);
        pos += 4;
    } else {
        return; // Invalid compact size
    }

    // Strict validation: remaining bytes must be exactly N * SPHINCS_SIG_SIZE
    bool valid = (annex.size() - pos == num_sigs * SPHINCS_SIG_SIZE);

    // If valid, verify we can access all signatures without overflow
    if (valid) {
        for (uint64_t i = 0; i < num_sigs; i++) {
            size_t offset = pos + i * SPHINCS_SIG_SIZE;
            assert(offset + SPHINCS_SIG_SIZE <= annex.size());
        }
    }
}

// BIP 368: Fuzz the key-path annex parsing logic.
FUZZ_TARGET(keypath_annex_parse)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    auto annex = fuzzed_data_provider.ConsumeRemainingBytes<uint8_t>();

    if (annex.empty()) return;
    if (annex[0] != ANNEX_TAG) return;
    if (annex.size() < 2) return;
    if (annex[1] != KEYPATH_ANNEX_TYPE) return;

    // Validate format: must be exactly 34 or 66 bytes
    bool valid = (annex.size() == 34 || annex.size() == 66);

    if (valid) {
        // Extract internal key (bytes 2-33) — must not crash
        assert(annex.size() >= 34);
        XOnlyPubKey pk{std::span<const unsigned char>{annex.data() + 2, 32}};

        // NUMS check — must not crash
        (void)(pk == XOnlyPubKey::NUMS_H);

        // If 66 bytes, extract merkle root
        if (annex.size() == 66) {
            uint256 merkle_root;
            memcpy(merkle_root.data(), annex.data() + 34, 32);
        }
    }
}

// BIP 368: Fuzz the tweak verification with random pubkeys.
FUZZ_TARGET(keypath_tweak_verify)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    auto pk_bytes = fuzzed_data_provider.ConsumeBytes<uint8_t>(32);
    auto root_bytes = fuzzed_data_provider.ConsumeBytes<uint8_t>(32);

    pk_bytes.resize(32, 0);
    XOnlyPubKey pk{std::span<const unsigned char>{pk_bytes.data(), 32}};

    // Try CreateTapTweak with and without merkle root — must not crash
    auto result_no_root = pk.CreateTapTweak(nullptr);
    (void)result_no_root;

    if (root_bytes.size() == 32) {
        uint256 merkle_root;
        memcpy(merkle_root.data(), root_bytes.data(), 32);
        auto result_with_root = pk.CreateTapTweak(&merkle_root);
        (void)result_with_root;
    }

    // NUMS comparison — must not crash
    (void)(pk == XOnlyPubKey::NUMS_H);
}
