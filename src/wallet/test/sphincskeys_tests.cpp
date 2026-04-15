// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sphincsplus.h>
#include <key.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <wallet/sphincskeys.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <vector>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(sphincskeys_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(generate_and_sizes)
{
    // Generate a key from random seed components
    unsigned char sk_seed[16], sk_prf[16], pk_seed[16];
    GetRandBytes(sk_seed);
    GetRandBytes(sk_prf);
    GetRandBytes(pk_seed);

    SphincsKey key;
    BOOST_CHECK(!key.IsValid());

    key.Generate(sk_seed, sk_prf, pk_seed);
    BOOST_CHECK(key.IsValid());

    // Verify sizes
    BOOST_CHECK_EQUAL(SphincsKey::SECRET_SIZE, 64u);
    BOOST_CHECK_EQUAL(SphincsKey::PUBLIC_SIZE, 32u);
    BOOST_CHECK_EQUAL(SphincsKey::SIGNATURE_SIZE, 4080u);
    BOOST_CHECK(key.SecretData() != nullptr);
    BOOST_CHECK(key.PubkeyData() != nullptr);
}

BOOST_AUTO_TEST_CASE(generate_deterministic)
{
    // Same seed components → same key pair
    unsigned char sk_seed[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    unsigned char sk_prf[16] = {17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    unsigned char pk_seed[16] = {33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48};

    SphincsKey key1, key2;
    key1.Generate(sk_seed, sk_prf, pk_seed);
    key2.Generate(sk_seed, sk_prf, pk_seed);

    BOOST_CHECK(key1.IsValid());
    BOOST_CHECK(key2.IsValid());
    BOOST_CHECK(std::memcmp(key1.SecretData(), key2.SecretData(), SphincsKey::SECRET_SIZE) == 0);
    BOOST_CHECK(std::memcmp(key1.PubkeyData(), key2.PubkeyData(), SphincsKey::PUBLIC_SIZE) == 0);
}

BOOST_AUTO_TEST_CASE(generate_different_seeds_different_keys)
{
    unsigned char seed_a[16] = {0};
    unsigned char seed_b[16] = {1};
    unsigned char common_prf[16] = {0};
    unsigned char common_pk[16] = {0};

    SphincsKey key1, key2;
    key1.Generate(seed_a, common_prf, common_pk);
    key2.Generate(seed_b, common_prf, common_pk);

    BOOST_CHECK(key1.IsValid());
    BOOST_CHECK(key2.IsValid());
    // Different sk_seed → different keys
    BOOST_CHECK(std::memcmp(key1.PubkeyData(), key2.PubkeyData(), SphincsKey::PUBLIC_SIZE) != 0);
}

BOOST_AUTO_TEST_CASE(sign_and_verify)
{
    unsigned char sk_seed[16], sk_prf[16], pk_seed[16];
    GetRandBytes(sk_seed);
    GetRandBytes(sk_prf);
    GetRandBytes(pk_seed);

    SphincsKey key;
    key.Generate(sk_seed, sk_prf, pk_seed);
    BOOST_CHECK(key.IsValid());

    // Sign a random message hash
    uint256 msg_hash = GetRandHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(msg_hash, sig));
    BOOST_CHECK_EQUAL(sig.size(), SphincsKey::SIGNATURE_SIZE);

    // Verify with the consensus verification function
    std::span<const uint8_t> pk_span{key.PubkeyData(), SphincsKey::PUBLIC_SIZE};
    std::span<const uint8_t> sig_span{sig.data(), sig.size()};
    BOOST_CHECK(VerifySphincsSignature(pk_span, sig_span, msg_hash));

    // Corrupt the signature → verification should fail
    sig[0] ^= 0xff;
    std::span<const uint8_t> bad_sig_span{sig.data(), sig.size()};
    BOOST_CHECK(!VerifySphincsSignature(pk_span, bad_sig_span, msg_hash));
}

BOOST_AUTO_TEST_CASE(sign_invalid_key_fails)
{
    SphincsKey key;
    BOOST_CHECK(!key.IsValid());

    uint256 msg_hash = GetRandHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(!key.Sign(msg_hash, sig));
    BOOST_CHECK(sig.empty());
}

BOOST_AUTO_TEST_CASE(load_roundtrip)
{
    unsigned char sk_seed[16], sk_prf[16], pk_seed[16];
    GetRandBytes(sk_seed);
    GetRandBytes(sk_prf);
    GetRandBytes(pk_seed);

    SphincsKey original;
    original.Generate(sk_seed, sk_prf, pk_seed);
    BOOST_CHECK(original.IsValid());

    // Extract secret and pubkey
    CKeyingMaterial secret = original.GetSecret();
    BOOST_CHECK_EQUAL(secret.size(), SphincsKey::SECRET_SIZE);

    // Load into a new key
    SphincsKey loaded;
    BOOST_CHECK(loaded.Load(
        {reinterpret_cast<const unsigned char*>(secret.data()), secret.size()},
        {original.PubkeyData(), SphincsKey::PUBLIC_SIZE}));
    BOOST_CHECK(loaded.IsValid());

    // Verify keys match
    BOOST_CHECK(std::memcmp(original.SecretData(), loaded.SecretData(), SphincsKey::SECRET_SIZE) == 0);
    BOOST_CHECK(std::memcmp(original.PubkeyData(), loaded.PubkeyData(), SphincsKey::PUBLIC_SIZE) == 0);
}

BOOST_AUTO_TEST_CASE(load_wrong_pubkey_fails)
{
    unsigned char sk_seed[16], sk_prf[16], pk_seed[16];
    GetRandBytes(sk_seed);
    GetRandBytes(sk_prf);
    GetRandBytes(pk_seed);

    SphincsKey original;
    original.Generate(sk_seed, sk_prf, pk_seed);

    CKeyingMaterial secret = original.GetSecret();

    // Try loading with a wrong pubkey
    std::array<unsigned char, 32> wrong_pubkey{};
    wrong_pubkey[0] = 0xff;  // Definitely doesn't match

    SphincsKey loaded;
    BOOST_CHECK(!loaded.Load(
        {reinterpret_cast<const unsigned char*>(secret.data()), secret.size()},
        wrong_pubkey));
    BOOST_CHECK(!loaded.IsValid());
}

BOOST_AUTO_TEST_CASE(load_wrong_sizes_fail)
{
    SphincsKey key;

    // Too short secret
    std::array<unsigned char, 32> short_secret{};
    std::array<unsigned char, 32> pubkey{};
    BOOST_CHECK(!key.Load(short_secret, pubkey));

    // Too short pubkey
    std::array<unsigned char, 64> secret{};
    std::array<unsigned char, 16> short_pubkey{};
    BOOST_CHECK(!key.Load(secret, short_pubkey));
}

BOOST_AUTO_TEST_CASE(derive_from_master_deterministic)
{
    // Create a master extended key
    CKey master_priv;
    master_priv.MakeNewKey(true);
    CExtKey master_ext;
    master_ext.key = master_priv;
    GetRandBytes(master_ext.chaincode);

    // Derive with same path → same key
    std::vector<uint32_t> path = {0x8000018B, 0x80000000, 0x80000000}; // m/395'/0'/0'
    SphincsKey key1 = SphincsKey::DeriveFromMaster(master_ext, path);
    SphincsKey key2 = SphincsKey::DeriveFromMaster(master_ext, path);

    BOOST_CHECK(key1.IsValid());
    BOOST_CHECK(key2.IsValid());
    BOOST_CHECK(std::memcmp(key1.SecretData(), key2.SecretData(), SphincsKey::SECRET_SIZE) == 0);
    BOOST_CHECK(std::memcmp(key1.PubkeyData(), key2.PubkeyData(), SphincsKey::PUBLIC_SIZE) == 0);
}

BOOST_AUTO_TEST_CASE(derive_from_master_different_path)
{
    CKey master_priv;
    master_priv.MakeNewKey(true);
    CExtKey master_ext;
    master_ext.key = master_priv;
    GetRandBytes(master_ext.chaincode);

    // Different paths → different keys
    std::vector<uint32_t> path_a = {0x8000018B, 0x80000000, 0x80000000}; // m/395'/0'/0'
    std::vector<uint32_t> path_b = {0x8000018B, 0x80000000, 0x80000001}; // m/395'/0'/1'

    SphincsKey key_a = SphincsKey::DeriveFromMaster(master_ext, path_a);
    SphincsKey key_b = SphincsKey::DeriveFromMaster(master_ext, path_b);

    BOOST_CHECK(key_a.IsValid());
    BOOST_CHECK(key_b.IsValid());
    BOOST_CHECK(std::memcmp(key_a.PubkeyData(), key_b.PubkeyData(), SphincsKey::PUBLIC_SIZE) != 0);
}

BOOST_AUTO_TEST_CASE(derive_from_master_different_master)
{
    // Different master keys → different SPHINCS+ keys (same path)
    CKey priv_a, priv_b;
    priv_a.MakeNewKey(true);
    priv_b.MakeNewKey(true);

    CExtKey ext_a, ext_b;
    ext_a.key = priv_a;
    ext_b.key = priv_b;
    GetRandBytes(ext_a.chaincode);
    GetRandBytes(ext_b.chaincode);

    std::vector<uint32_t> path = {0x8000018B, 0x80000000, 0x80000000};

    SphincsKey key_a = SphincsKey::DeriveFromMaster(ext_a, path);
    SphincsKey key_b = SphincsKey::DeriveFromMaster(ext_b, path);

    BOOST_CHECK(key_a.IsValid());
    BOOST_CHECK(key_b.IsValid());
    BOOST_CHECK(std::memcmp(key_a.PubkeyData(), key_b.PubkeyData(), SphincsKey::PUBLIC_SIZE) != 0);
}

BOOST_AUTO_TEST_CASE(derive_and_sign_verify)
{
    CKey master_priv;
    master_priv.MakeNewKey(true);
    CExtKey master_ext;
    master_ext.key = master_priv;
    GetRandBytes(master_ext.chaincode);

    std::vector<uint32_t> path = {0x8000018B, 0x80000000, 0x80000000};
    SphincsKey key = SphincsKey::DeriveFromMaster(master_ext, path);
    BOOST_CHECK(key.IsValid());

    // Sign and verify
    uint256 msg_hash = GetRandHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(msg_hash, sig));
    BOOST_CHECK_EQUAL(sig.size(), SphincsKey::SIGNATURE_SIZE);

    std::span<const uint8_t> pk_span{key.PubkeyData(), SphincsKey::PUBLIC_SIZE};
    std::span<const uint8_t> sig_span{sig.data(), sig.size()};
    BOOST_CHECK(VerifySphincsSignature(pk_span, sig_span, msg_hash));
}

BOOST_AUTO_TEST_CASE(copy_constructor)
{
    unsigned char sk_seed[16], sk_prf[16], pk_seed[16];
    GetRandBytes(sk_seed);
    GetRandBytes(sk_prf);
    GetRandBytes(pk_seed);

    SphincsKey original;
    original.Generate(sk_seed, sk_prf, pk_seed);
    BOOST_CHECK(original.IsValid());

    // Copy construct
    SphincsKey copied(original);
    BOOST_CHECK(copied.IsValid());
    BOOST_CHECK(std::memcmp(original.SecretData(), copied.SecretData(), SphincsKey::SECRET_SIZE) == 0);
    BOOST_CHECK(std::memcmp(original.PubkeyData(), copied.PubkeyData(), SphincsKey::PUBLIC_SIZE) == 0);

    // Verify the copy can sign independently
    uint256 msg_hash = GetRandHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(copied.Sign(msg_hash, sig));

    std::span<const uint8_t> pk_span{copied.PubkeyData(), SphincsKey::PUBLIC_SIZE};
    std::span<const uint8_t> sig_span{sig.data(), sig.size()};
    BOOST_CHECK(VerifySphincsSignature(pk_span, sig_span, msg_hash));
}

// === Edge case tests ===

BOOST_AUTO_TEST_CASE(generate_from_zero_seeds)
{
    unsigned char zeros[16] = {0};
    SphincsKey key;
    key.Generate(zeros, zeros, zeros);
    BOOST_CHECK(key.IsValid());

    // Should still be able to sign
    uint256 msg = GetRandHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(msg, sig));
    BOOST_CHECK_EQUAL(sig.size(), SphincsKey::SIGNATURE_SIZE);
}

BOOST_AUTO_TEST_CASE(sign_zero_hash)
{
    unsigned char seed[16];
    GetRandBytes(seed);
    SphincsKey key;
    key.Generate(seed, seed, seed);

    uint256 zero_hash{};  // All zeros
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(zero_hash, sig));
    BOOST_CHECK_EQUAL(sig.size(), SphincsKey::SIGNATURE_SIZE);

    std::span<const uint8_t> pk{key.PubkeyData(), SphincsKey::PUBLIC_SIZE};
    BOOST_CHECK(VerifySphincsSignature(pk, sig, zero_hash));
}

BOOST_AUTO_TEST_CASE(load_truncated_secret_fails)
{
    std::array<unsigned char, 32> short_secret{};
    std::array<unsigned char, 32> pubkey{};
    SphincsKey key;
    BOOST_CHECK(!key.Load(short_secret, pubkey));
    BOOST_CHECK(!key.IsValid());
}

BOOST_AUTO_TEST_CASE(load_oversized_secret_fails)
{
    std::array<unsigned char, 128> long_secret{};
    std::array<unsigned char, 32> pubkey{};
    SphincsKey key;
    BOOST_CHECK(!key.Load(std::span<const unsigned char>{long_secret.data(), 128},
                          pubkey));
    BOOST_CHECK(!key.IsValid());
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
