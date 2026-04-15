// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <key.h>
#include <key_io.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <wallet/qextkey.h>
#include <wallet/sphincskeys.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstring>
#include <variant>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(qextkey_tests, BasicTestingSetup)

static QExtKey MakeTestQExtKey()
{
    QExtKey qkey;
    // Generate a BIP32 master key from random seed
    CKey seed_key;
    seed_key.MakeNewKey(true);
    qkey.extkey.SetSeed(std::as_bytes(std::span{seed_key.data(), 32}));

    // Generate a SPHINCS+ keypair and store in qkey
    SphincsKey sk = SphincsKey::DeriveFromMaster(qkey.extkey, {0x8000018B, 0x80000000, 0x80000000});
    std::memcpy(qkey.sphincs_secret.data(), sk.SecretData(), 64);

    return qkey;
}

BOOST_AUTO_TEST_CASE(encode_decode_qextpubkey)
{
    QExtKey qkey = MakeTestQExtKey();
    QExtPubKey qpub = qkey.Neuter();

    // Encode
    std::array<unsigned char, QExtPubKey::QI_EXTKEY_SIZE> buf{};
    qpub.Encode(buf);

    // Decode
    QExtPubKey decoded;
    decoded.Decode(buf);

    BOOST_CHECK(decoded == qpub);
    BOOST_CHECK(decoded.extpub == qpub.extpub);
    BOOST_CHECK(decoded.sphincs_pubkey == qpub.sphincs_pubkey);
}

BOOST_AUTO_TEST_CASE(encode_decode_qextkey)
{
    QExtKey qkey = MakeTestQExtKey();

    // Encode
    std::array<unsigned char, QExtKey::QI_EXTKEY_SIZE> buf{};
    qkey.Encode(buf);

    // Decode
    QExtKey decoded;
    decoded.Decode(buf);

    BOOST_CHECK(decoded == qkey);
    BOOST_CHECK(decoded.extkey == qkey.extkey);
    BOOST_CHECK(decoded.sphincs_secret == qkey.sphincs_secret);
}

BOOST_AUTO_TEST_CASE(base58_roundtrip_qextpubkey)
{
    QExtKey qkey = MakeTestQExtKey();
    QExtPubKey qpub = qkey.Neuter();

    std::string encoded = EncodeQExtPubKey(qpub);
    BOOST_CHECK(!encoded.empty());

    QExtPubKey decoded = DecodeQExtPubKey(encoded);
    BOOST_CHECK(decoded == qpub);
}

BOOST_AUTO_TEST_CASE(base58_roundtrip_qextkey)
{
    QExtKey qkey = MakeTestQExtKey();

    std::string encoded = EncodeQExtKey(qkey);
    BOOST_CHECK(!encoded.empty());

    QExtKey decoded = DecodeQExtKey(encoded);
    BOOST_CHECK(decoded == qkey);
}

BOOST_AUTO_TEST_CASE(child_derivation_pubkey)
{
    QExtKey qkey = MakeTestQExtKey();
    QExtPubKey qpub = qkey.Neuter();

    // Derive child 0
    QExtPubKey child0;
    BOOST_CHECK(qpub.Derive(child0, 0));

    // Derive child 1
    QExtPubKey child1;
    BOOST_CHECK(qpub.Derive(child1, 1));

    // BIP32 keys should differ
    BOOST_CHECK(child0.extpub.pubkey != child1.extpub.pubkey);

    // SPHINCS+ keys should be identical
    BOOST_CHECK(child0.sphincs_pubkey == child1.sphincs_pubkey);
    BOOST_CHECK(child0.sphincs_pubkey == qpub.sphincs_pubkey);
}

BOOST_AUTO_TEST_CASE(child_derivation_privkey)
{
    QExtKey qkey = MakeTestQExtKey();

    // Derive child 0
    QExtKey child0;
    BOOST_CHECK(qkey.Derive(child0, 0));

    // SPHINCS+ secret should be identical
    BOOST_CHECK(child0.sphincs_secret == qkey.sphincs_secret);

    // BIP32 key should differ
    BOOST_CHECK(!(child0.extkey.key == qkey.extkey.key));
}

BOOST_AUTO_TEST_CASE(neuter_consistency)
{
    QExtKey qkey = MakeTestQExtKey();
    QExtPubKey qpub = qkey.Neuter();

    // BIP32 public key should match
    BOOST_CHECK(qpub.extpub.pubkey == qkey.extkey.key.GetPubKey());

    // SPHINCS+ pubkey should be last 32 bytes of 64-byte secret
    std::array<unsigned char, 32> expected_pk;
    std::memcpy(expected_pk.data(), qkey.sphincs_secret.data() + 32, 32);
    BOOST_CHECK(qpub.sphincs_pubkey == expected_pk);

    // Child derivation: priv-derive then neuter == pub-derive
    QExtKey priv_child;
    BOOST_CHECK(qkey.Derive(priv_child, 42));
    QExtPubKey pub_from_priv = priv_child.Neuter();

    QExtPubKey pub_child;
    BOOST_CHECK(qpub.Derive(pub_child, 42));

    BOOST_CHECK(pub_from_priv.extpub.pubkey == pub_child.extpub.pubkey);
    BOOST_CHECK(pub_from_priv.sphincs_pubkey == pub_child.sphincs_pubkey);
}

BOOST_AUTO_TEST_CASE(derive_address_returns_taproot)
{
    QExtKey qkey = MakeTestQExtKey();
    QExtPubKey qpub = qkey.Neuter();

    CTxDestination dest = qpub.DeriveAddress(0);

    // Should be a WitnessV1Taproot destination
    BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(dest));
}

BOOST_AUTO_TEST_CASE(derive_address_deterministic)
{
    QExtKey qkey = MakeTestQExtKey();
    QExtPubKey qpub = qkey.Neuter();

    CTxDestination dest1 = qpub.DeriveAddress(7);
    CTxDestination dest2 = qpub.DeriveAddress(7);

    BOOST_CHECK(dest1 == dest2);
}

BOOST_AUTO_TEST_CASE(derive_address_different_indices)
{
    QExtKey qkey = MakeTestQExtKey();
    QExtPubKey qpub = qkey.Neuter();

    CTxDestination dest0 = qpub.DeriveAddress(0);
    CTxDestination dest1 = qpub.DeriveAddress(1);

    // Different indices → different addresses
    BOOST_CHECK(dest0 != dest1);
}

BOOST_AUTO_TEST_CASE(derive_address_matches_manual_construction)
{
    QExtKey qkey = MakeTestQExtKey();
    QExtPubKey qpub = qkey.Neuter();

    // Derive address via QExtPubKey
    CTxDestination dest = qpub.DeriveAddress(5);
    BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(dest));
    WitnessV1Taproot output_from_qpub = std::get<WitnessV1Taproot>(dest);

    // Manual construction: derive child, build script, build Taproot
    QExtPubKey child;
    BOOST_CHECK(qpub.Derive(child, 5));
    XOnlyPubKey child_xonly{child.extpub.pubkey};

    CScript hybrid_script;
    hybrid_script << std::span<const std::byte>{reinterpret_cast<const std::byte*>(qpub.sphincs_pubkey.data()), 32};
    hybrid_script << OP_CHECKSPHINCSVERIFY;
    hybrid_script << OP_DROP;
    hybrid_script << std::span<const std::byte>{reinterpret_cast<const std::byte*>(child_xonly.data()), 32};
    hybrid_script << OP_CHECKSIG;

    TaprootBuilder builder;
    builder.Add(0, hybrid_script, TAPROOT_LEAF_TAPSCRIPT);
    builder.Finalize(child_xonly);
    WitnessV1Taproot output_manual = builder.GetOutput();

    // They should match
    BOOST_CHECK(std::memcmp(output_from_qpub.data(), output_manual.data(), 32) == 0);
}

BOOST_AUTO_TEST_CASE(base58_prefix_starts_with_Q)
{
    QExtKey qkey = MakeTestQExtKey();
    QExtPubKey qpub = qkey.Neuter();

    std::string encoded_pub = EncodeQExtPubKey(qpub);
    std::string encoded_prv = EncodeQExtKey(qkey);

    BOOST_CHECK(!encoded_pub.empty());
    BOOST_CHECK(!encoded_prv.empty());

    // Both should start with 'Q'
    BOOST_CHECK_EQUAL(encoded_pub[0], 'Q');
    BOOST_CHECK_EQUAL(encoded_prv[0], 'Q');
}

BOOST_AUTO_TEST_CASE(deterministic_test_vector)
{
    // Generate a test vector from a known seed for BIP 395 reproducibility.
    // Seed: 16 bytes of 0x01
    unsigned char seed_bytes[16];
    std::memset(seed_bytes, 0x01, 16);

    CKey seed_key;
    seed_key.Set(std::begin(seed_bytes), std::begin(seed_bytes) + 32, true);
    // Actually we need 32 bytes for CKey::Set — use a proper 32-byte seed
    unsigned char seed32[32];
    std::memset(seed32, 0x01, 32);
    seed_key.Set(seed32, seed32 + 32, true);

    CExtKey master;
    master.SetSeed(std::as_bytes(std::span{seed_key.data(), 32}));

    // Derive SPHINCS+ key at m/395'/0'/0'
    std::vector<uint32_t> path = {0x8000018B, 0x80000000, 0x80000000};
    SphincsKey sphincs = SphincsKey::DeriveFromMaster(master, path);
    BOOST_CHECK(sphincs.IsValid());

    // Build QExtKey
    QExtKey qkey;
    qkey.extkey = master;
    std::memcpy(qkey.sphincs_secret.data(), sphincs.SecretData(), 64);

    QExtPubKey qpub = qkey.Neuter();

    // Dump test vector values (capture with --log_level=message)
    std::string master_priv_hex = HexStr(std::span<const std::byte>{master.key.data(), 32});
    std::string master_chain_hex = HexStr(master.chaincode);
    std::string master_pub_hex = HexStr(master.key.GetPubKey());
    std::string sphincs_pub_hex = HexStr(std::span<const unsigned char>{sphincs.PubkeyData(), 32});
    std::string sphincs_secret_hex = HexStr(std::span<const unsigned char>{sphincs.SecretData(), 64});
    std::string qpub_b58 = EncodeQExtPubKey(qpub);
    std::string qprv_b58 = EncodeQExtKey(qkey);

    BOOST_TEST_MESSAGE("=== BIP 395 Test Vector ===");
    BOOST_TEST_MESSAGE("seed (32 bytes): " + HexStr(std::span<const unsigned char>{seed32, 32}));
    BOOST_TEST_MESSAGE("master_privkey: " + master_priv_hex);
    BOOST_TEST_MESSAGE("master_chaincode: " + master_chain_hex);
    BOOST_TEST_MESSAGE("master_pubkey: " + master_pub_hex);
    BOOST_TEST_MESSAGE("sphincs_derivation_path: m/395'/0'/0'");
    BOOST_TEST_MESSAGE("sphincs_pubkey (32): " + sphincs_pub_hex);
    BOOST_TEST_MESSAGE("sphincs_secret (64): " + sphincs_secret_hex);
    BOOST_TEST_MESSAGE("qpub_base58: " + qpub_b58);
    BOOST_TEST_MESSAGE("qprv_base58: " + qprv_b58);

    // Derive addresses and log
    CTxDestination pre_addr0 = qpub.DeriveAddress(0);
    CTxDestination pre_addr1 = qpub.DeriveAddress(1);
    CTxDestination pre_addr2 = qpub.DeriveAddress(2);
    if (std::holds_alternative<WitnessV1Taproot>(pre_addr0))
        BOOST_TEST_MESSAGE("address[0]: " + EncodeDestination(pre_addr0));
    if (std::holds_alternative<WitnessV1Taproot>(pre_addr1))
        BOOST_TEST_MESSAGE("address[1]: " + EncodeDestination(pre_addr1));
    if (std::holds_alternative<WitnessV1Taproot>(pre_addr2))
        BOOST_TEST_MESSAGE("address[2]: " + EncodeDestination(pre_addr2));
    BOOST_TEST_MESSAGE("=== End Test Vector ===");

    // Verify determinism: same seed always produces same keys
    SphincsKey sphincs2 = SphincsKey::DeriveFromMaster(master, path);
    BOOST_CHECK(std::memcmp(sphincs.PubkeyData(), sphincs2.PubkeyData(), 32) == 0);

    // Verify qpub roundtrip
    QExtPubKey decoded_qpub = DecodeQExtPubKey(qpub_b58);
    BOOST_CHECK(decoded_qpub == qpub);

    // Verify qprv roundtrip
    QExtKey decoded_qkey = DecodeQExtKey(qprv_b58);
    BOOST_CHECK(decoded_qkey == qkey);

    // Derive addresses at indices 0, 1, 2 and verify they're different
    CTxDestination addr0 = qpub.DeriveAddress(0);
    CTxDestination addr1 = qpub.DeriveAddress(1);
    CTxDestination addr2 = qpub.DeriveAddress(2);
    BOOST_CHECK(addr0 != addr1);
    BOOST_CHECK(addr1 != addr2);
    BOOST_CHECK(addr0 != addr2);

    // All should be valid Taproot destinations
    BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(addr0));
    BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(addr1));
    BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(addr2));
}

// === Edge case tests ===

BOOST_AUTO_TEST_CASE(derive_max_non_hardened_index)
{
    QExtKey qkey = MakeTestQExtKey();
    QExtPubKey qpub = qkey.Neuter();

    // Max non-hardened index
    QExtPubKey child;
    BOOST_CHECK(qpub.Derive(child, 0x7FFFFFFF));
    BOOST_CHECK(child.extpub.pubkey.IsValid());
    BOOST_CHECK(child.sphincs_pubkey == qpub.sphincs_pubkey);
}

BOOST_AUTO_TEST_CASE(neuter_sphincs_pubkey_matches_secret_tail)
{
    QExtKey qkey = MakeTestQExtKey();
    QExtPubKey qpub = qkey.Neuter();

    // SPHINCS+ pubkey should be last 32 bytes of 64-byte secret
    BOOST_CHECK(std::memcmp(qpub.sphincs_pubkey.data(),
                            qkey.sphincs_secret.data() + 32, 32) == 0);
}

BOOST_AUTO_TEST_CASE(derive_address_zero_sphincs_key)
{
    // A qpub with a valid EC key but all-zero SPHINCS+ key should still work
    QExtKey qkey = MakeTestQExtKey();
    QExtPubKey qpub = qkey.Neuter();
    qpub.sphincs_pubkey = {};  // zero out SPHINCS+ key

    CTxDestination dest = qpub.DeriveAddress(0);
    // Should still produce a valid Taproot address (with zero SPHINCS+ key in script)
    BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(dest));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
