// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <qextkey.h>
#include <random.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <wallet/sphincskeys.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(qis_descriptor_tests, BasicTestingSetup)

// Helper: create a descriptor string for qis() inside tr()
static std::string MakeQISDescriptor(const std::string& internal_key_wif,
                                      const std::string& sphincs_hex,
                                      const std::string& ec_key_hex)
{
    // Single tapleaf — no braces needed
    return "tr(" + internal_key_wif + ",qis(" + sphincs_hex + "," + ec_key_hex + "))";
}

BOOST_AUTO_TEST_CASE(parse_qis_descriptor)
{
    // Generate keys
    auto internal_key = GenerateRandomKey();
    auto ec_key = GenerateRandomKey();

    // Generate SPHINCS+ key
    SphincsKey sphincs;
    unsigned char seed[16];
    GetRandBytes(seed);
    sphincs.Generate(seed, seed, seed);

    std::string sphincs_hex = HexStr(std::span<const unsigned char>{sphincs.PubkeyData(), 32});
    XOnlyPubKey ec_xonly{ec_key.GetPubKey()};
    std::string ec_hex = HexStr(std::span<const unsigned char>{ec_xonly.data(), 32});
    std::string desc_str = MakeQISDescriptor(EncodeSecret(internal_key), sphincs_hex, ec_hex);

    // Parse the descriptor
    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error);
    BOOST_CHECK_MESSAGE(!descs.empty(), "Parse failed: " + error);
    BOOST_CHECK_EQUAL(descs.size(), 1u);
}

BOOST_AUTO_TEST_CASE(qis_produces_correct_script)
{
    // Generate keys
    auto internal_key = GenerateRandomKey();
    auto ec_key = GenerateRandomKey();

    SphincsKey sphincs;
    unsigned char seed[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    sphincs.Generate(seed, seed, seed);

    std::string sphincs_hex = HexStr(std::span<const unsigned char>{sphincs.PubkeyData(), 32});
    XOnlyPubKey ec_xonly{ec_key.GetPubKey()};
    std::string ec_hex = HexStr(std::span<const unsigned char>{ec_xonly.data(), 32});
    std::string desc_str = MakeQISDescriptor(EncodeSecret(internal_key), sphincs_hex, ec_hex);

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error);
    BOOST_REQUIRE(!descs.empty());

    // Expand at index 0
    FlatSigningProvider provider;
    std::vector<CScript> scripts;
    descs[0]->Expand(0, keys, scripts, provider);
    BOOST_CHECK_EQUAL(scripts.size(), 1u);

    // The output should be a Taproot script (OP_1 <32-byte key>)
    CScript& output_script = scripts[0];
    BOOST_CHECK_EQUAL(output_script.size(), 34u); // OP_1 + push32 + 32 bytes
    BOOST_CHECK_EQUAL(output_script[0], 0x51); // OP_1 (witness v1)

    // Check that the Taproot spend data contains the hybrid script
    auto tr_trees = provider.tr_trees;
    BOOST_CHECK_EQUAL(tr_trees.size(), 1u);

    // Get the spend data and check the script tree
    for (const auto& [output, builder] : tr_trees) {
        TaprootSpendData spend_data = builder.GetSpendData();
        BOOST_CHECK(!spend_data.scripts.empty());

        // Find the script and verify it contains OP_CHECKSPHINCSVERIFY
        for (const auto& [script_leaf, control_blocks] : spend_data.scripts) {
            const auto& script = script_leaf.first;
            // Script should contain OP_CHECKSPHINCSVERIFY (0xb3)
            bool found_csv = false;
            for (size_t i = 0; i < script.size(); ++i) {
                if (script[i] == OP_CHECKSPHINCSVERIFY) {
                    found_csv = true;
                    break;
                }
            }
            BOOST_CHECK_MESSAGE(found_csv, "Hybrid script should contain OP_CHECKSPHINCSVERIFY");

            // Script should also contain OP_CHECKSIG (0xac)
            bool found_cs = false;
            for (size_t i = 0; i < script.size(); ++i) {
                if (script[i] == OP_CHECKSIG) {
                    found_cs = true;
                    break;
                }
            }
            BOOST_CHECK_MESSAGE(found_cs, "Hybrid script should contain OP_CHECKSIG");

            // Script should contain OP_DROP (0x75)
            bool found_drop = false;
            for (size_t i = 0; i < script.size(); ++i) {
                if (script[i] == OP_DROP) {
                    found_drop = true;
                    break;
                }
            }
            BOOST_CHECK_MESSAGE(found_drop, "Hybrid script should contain OP_DROP");
        }
    }
}

BOOST_AUTO_TEST_CASE(qis_descriptor_string_roundtrip)
{
    auto internal_key = GenerateRandomKey();
    auto ec_key = GenerateRandomKey();

    SphincsKey sphincs;
    unsigned char seed[16] = {42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42};
    sphincs.Generate(seed, seed, seed);

    std::string sphincs_hex = HexStr(std::span<const unsigned char>{sphincs.PubkeyData(), 32});
    XOnlyPubKey ec_xonly{ec_key.GetPubKey()};
    std::string ec_hex = HexStr(std::span<const unsigned char>{ec_xonly.data(), 32});
    std::string desc_str = MakeQISDescriptor(EncodeSecret(internal_key), sphincs_hex, ec_hex);

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error);
    BOOST_REQUIRE(!descs.empty());

    // Get the descriptor string back (public form)
    std::string out_str = descs[0]->ToString();

    // Re-parse the output
    auto descs2 = Parse(out_str, keys, error);
    BOOST_CHECK_MESSAGE(!descs2.empty(), "Re-parse failed: " + error);

    // Both should expand to the same script
    std::vector<CScript> scripts1, scripts2;
    FlatSigningProvider prov1, prov2;
    descs[0]->Expand(0, keys, scripts1, prov1);
    descs2[0]->Expand(0, keys, scripts2, prov2);
    BOOST_CHECK_EQUAL(scripts1.size(), scripts2.size());
    if (!scripts1.empty() && !scripts2.empty()) {
        BOOST_CHECK(scripts1[0] == scripts2[0]);
    }
}

BOOST_AUTO_TEST_CASE(qis_only_in_p2tr_context)
{
    auto key = GenerateRandomKey();
    SphincsKey sphincs;
    unsigned char seed[16] = {0};
    sphincs.Generate(seed, seed, seed);

    std::string sphincs_hex = HexStr(std::span<const unsigned char>{sphincs.PubkeyData(), 32});
    XOnlyPubKey xonly{key.GetPubKey()};
    std::string key_hex = HexStr(std::span<const unsigned char>{xonly.data(), 32});

    // qis() at top level should fail
    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse("qis(" + sphincs_hex + "," + key_hex + ")", keys, error);
    BOOST_CHECK(descs.empty()); // Should fail — qis() only valid inside tr()
}

BOOST_AUTO_TEST_CASE(qis_wrong_sphincs_key_size)
{
    auto internal_key = GenerateRandomKey();
    auto ec_key = GenerateRandomKey();
    XOnlyPubKey ec_xonly{ec_key.GetPubKey()};
    std::string ec_hex = HexStr(std::span<const unsigned char>{ec_xonly.data(), 32});

    // 16-byte hex (too short for SPHINCS+ key)
    std::string short_hex = "abababababababababababababababab";

    std::string desc_str = MakeQISDescriptor(EncodeSecret(internal_key), short_hex, ec_hex);
    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error);
    BOOST_CHECK(descs.empty()); // Should fail — SPHINCS+ key must be 32 bytes
}

BOOST_AUTO_TEST_CASE(qis_descriptor_checksum)
{
    auto internal_key = GenerateRandomKey();
    auto ec_key = GenerateRandomKey();

    SphincsKey sphincs;
    unsigned char seed[16] = {7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7};
    sphincs.Generate(seed, seed, seed);

    std::string sphincs_hex = HexStr(std::span<const unsigned char>{sphincs.PubkeyData(), 32});
    XOnlyPubKey ec_xonly{ec_key.GetPubKey()};
    std::string ec_hex = HexStr(std::span<const unsigned char>{ec_xonly.data(), 32});
    std::string desc_str = MakeQISDescriptor(EncodeSecret(internal_key), sphincs_hex, ec_hex);

    // First parse without checksum
    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error);
    BOOST_REQUIRE(!descs.empty());

    // Get the string with checksum (ToString adds it)
    std::string with_checksum = descs[0]->ToString();
    BOOST_CHECK(with_checksum.find('#') != std::string::npos);

    // Parse with require_checksum=true — should succeed
    auto descs2 = Parse(with_checksum, keys, error, /*require_checksum=*/true);
    BOOST_CHECK_MESSAGE(!descs2.empty(), "Parse with checksum failed: " + error);

    // Parse without checksum but require_checksum=true — should fail
    auto descs3 = Parse(desc_str, keys, error, /*require_checksum=*/true);
    BOOST_CHECK(descs3.empty()); // Should fail — checksum required but missing
}

// === qr() descriptor tests ===

static QExtPubKey MakeTestQPub()
{
    CKey seed_key;
    seed_key.MakeNewKey(true);
    CExtKey master;
    master.SetSeed(std::as_bytes(std::span{seed_key.data(), 32}));

    // Derive SPHINCS+ key
    SphincsKey sk = SphincsKey::DeriveFromMaster(master, {0x8000018B, 0x80000000, 0x80000000});

    QExtPubKey qpub;
    qpub.extpub = master.Neuter();
    std::copy(sk.PubkeyData(), sk.PubkeyData() + 32, qpub.sphincs_pubkey.begin());
    return qpub;
}

BOOST_AUTO_TEST_CASE(qr_parse_qpub)
{
    QExtPubKey qpub = MakeTestQPub();
    std::string qpub_str = EncodeQExtPubKey(qpub);
    std::string desc_str = "qr(" + qpub_str + "/0/*)";

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error);
    BOOST_CHECK_MESSAGE(!descs.empty(), "qr() parse failed: " + error);
    BOOST_CHECK_EQUAL(descs.size(), 1u);

    // Should produce a Taproot output
    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_CHECK(descs[0]->Expand(0, keys, scripts, out));
    BOOST_CHECK_EQUAL(scripts.size(), 1u);
    BOOST_CHECK_EQUAL(scripts[0].size(), 34u); // OP_1 + 32-byte key
    BOOST_CHECK_EQUAL(scripts[0][0], 0x51); // OP_1
}

BOOST_AUTO_TEST_CASE(qr_roundtrip_via_wallet_serialization_form)
{
    QExtPubKey qpub = MakeTestQPub();
    std::string input_desc = "qr(" + EncodeQExtPubKey(qpub) + "/0/*)";

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(input_desc, keys, error);
    BOOST_REQUIRE_MESSAGE(!descs.empty(), "qr() parse failed: " + error);

    const std::string serialized = descs[0]->ToString();
    BOOST_CHECK(serialized.rfind(input_desc + "#", 0) == 0);

    FlatSigningProvider roundtrip_keys;
    std::string roundtrip_error;
    auto roundtrip_descs = Parse(serialized, roundtrip_keys, roundtrip_error);
    BOOST_CHECK_MESSAGE(!roundtrip_descs.empty(), "serialized qr() parse failed: " + roundtrip_error);
    BOOST_CHECK(DescriptorID(*descs[0]) == DescriptorID(*roundtrip_descs[0]));
}

BOOST_AUTO_TEST_CASE(qr_rejects_noncanonical_wallet_form)
{
    QExtPubKey qpub = MakeTestQPub();
    std::string desc_str = "qr(" + HexStr(qpub.sphincs_pubkey) + "," + EncodeExtPubKey(qpub.extpub) + "/0/*)";

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error);
    BOOST_CHECK(descs.empty());
}

BOOST_AUTO_TEST_CASE(qr_wallet_db_write_is_canonical)
{
    QExtPubKey qpub = MakeTestQPub();
    const std::string qpub_str = EncodeQExtPubKey(qpub);
    const std::string canonical = "qr(" + qpub_str + "/0/*)";
    const std::string legacy = "qr(" + HexStr(qpub.sphincs_pubkey) + "," + EncodeExtPubKey(qpub.extpub) + "/0/*)";

    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

        FlatSigningProvider keys;
        std::string error;
        auto descs = Parse(canonical, keys, error);
        BOOST_REQUIRE_MESSAGE(!descs.empty(), "qr() parse failed: " + error);

        WalletDescriptor w_desc(std::move(descs[0]), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/2, /*next_index=*/0);
        auto add_result = wallet.AddWalletDescriptor(w_desc, keys, "", /*internal=*/false);
        BOOST_REQUIRE(add_result);
    }

    bool found_canonical{false};
    bool found_legacy{false};
    for (const auto& [key, value] : GetMockableDatabase(wallet).m_records) {
        const std::string value_str(reinterpret_cast<const char*>(value.data()), value.size());
        found_canonical |= value_str.find(canonical) != std::string::npos;
        found_legacy |= value_str.find(legacy) != std::string::npos;
    }

    BOOST_CHECK(found_canonical);
    BOOST_CHECK(!found_legacy);
}

BOOST_AUTO_TEST_CASE(qr_child_derivation_different_addresses)
{
    QExtPubKey qpub = MakeTestQPub();
    std::string qpub_str = EncodeQExtPubKey(qpub);
    std::string desc_str = "qr(" + qpub_str + "/0/*)";

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error);
    BOOST_REQUIRE(!descs.empty());

    // Expand at different indices — should produce different scripts
    std::vector<CScript> scripts0, scripts1;
    FlatSigningProvider out0, out1;
    BOOST_CHECK(descs[0]->Expand(0, keys, scripts0, out0));
    BOOST_CHECK(descs[0]->Expand(1, keys, scripts1, out1));
    BOOST_CHECK(scripts0[0] != scripts1[0]); // Different child keys → different outputs
}

BOOST_AUTO_TEST_CASE(qr_expansion_has_hybrid_leaf)
{
    QExtPubKey qpub = MakeTestQPub();
    std::string qpub_str = EncodeQExtPubKey(qpub);
    std::string desc_str = "qr(" + qpub_str + "/0/*)";

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error);
    BOOST_REQUIRE(!descs.empty());

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_CHECK(descs[0]->Expand(0, keys, scripts, out));

    // The Taproot tree should have a script containing OP_CHECKSPHINCSVERIFY
    BOOST_CHECK(!out.tr_trees.empty());
    for (const auto& [output, builder] : out.tr_trees) {
        TaprootSpendData spend_data = builder.GetSpendData();
        BOOST_CHECK(!spend_data.scripts.empty());
        bool found_csv = false;
        for (const auto& [script_leaf, control_blocks] : spend_data.scripts) {
            const auto& script = script_leaf.first;
            for (size_t i = 0; i < script.size(); ++i) {
                if (script[i] == OP_CHECKSPHINCSVERIFY) {
                    found_csv = true;
                    break;
                }
            }
        }
        BOOST_CHECK_MESSAGE(found_csv, "qr() output should contain hybrid leaf with OP_CHECKSPHINCSVERIFY");
    }
}

BOOST_AUTO_TEST_CASE(qr_top_context_only)
{
    QExtPubKey qpub = MakeTestQPub();
    std::string qpub_str = EncodeQExtPubKey(qpub);

    // qr() inside wsh() should fail
    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse("wsh(qr(" + qpub_str + "/0/*))", keys, error);
    BOOST_CHECK(descs.empty());
}

BOOST_AUTO_TEST_CASE(qr_invalid_key)
{
    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse("qr(invalidbase58/0/*)", keys, error);
    BOOST_CHECK(descs.empty());
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
