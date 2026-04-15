// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/sphincskeys.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(sphincskeys_db_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(sphincs_key_persists_across_reload)
{
    // Create a wallet with a descriptor
    auto db = CreateMockableWalletDatabase();
    CWallet wallet(m_node.chain.get(), "", std::move(db));
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    LOCK(wallet.cs_wallet);

    // Create a descriptor (tr type for Taproot)
    auto internal_key = GenerateRandomKey();
    std::string desc_str = "tr(" + EncodeSecret(internal_key) + ")";
    auto* spk_man = CreateDescriptor(wallet, desc_str, true);
    BOOST_REQUIRE(spk_man != nullptr);

    // Verify no SPHINCS+ key initially
    BOOST_CHECK(!spk_man->HasSphincsKey());

    // Create a master extended key and set up SPHINCS+ key
    CExtKey master;
    CKey seed_key;
    seed_key.MakeNewKey(true);
    master.SetSeed(std::as_bytes(std::span{seed_key.data(), 32}));

    std::vector<uint32_t> path = {0x8000018B, 0x80000000, 0x80000000};

    {
        WalletBatch batch(wallet.GetDatabase());
        BOOST_CHECK(spk_man->SetupSphincsKey(batch, master, path));
    }

    // Verify key exists
    BOOST_CHECK(spk_man->HasSphincsKey());
    auto pubkey1 = spk_man->GetSphincsPubkey();
    BOOST_REQUIRE(pubkey1.has_value());

    // Get the DB records for reload
    MockableData records = GetMockableDatabase(wallet).m_records;

    // Create a new wallet from the same DB records
    auto db2 = CreateMockableWalletDatabase(records);
    CWallet wallet2(m_node.chain.get(), "", std::move(db2));
    wallet2.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    {
        WalletBatch batch(wallet2.GetDatabase());
        batch.LoadWallet(&wallet2);
    }

    // Find the descriptor manager and verify SPHINCS+ key persists
    bool found = false;
    for (auto* mgr : wallet2.GetAllScriptPubKeyMans()) {
        auto* desc_mgr = dynamic_cast<DescriptorScriptPubKeyMan*>(mgr);
        if (desc_mgr && desc_mgr->HasSphincsKey()) {
            auto pubkey2 = desc_mgr->GetSphincsPubkey();
            BOOST_REQUIRE(pubkey2.has_value());
            BOOST_CHECK(*pubkey1 == *pubkey2);
            found = true;
            break;
        }
    }
    BOOST_CHECK_MESSAGE(found, "SPHINCS+ key should persist across wallet reload");
}

BOOST_AUTO_TEST_CASE(sphincs_key_deterministic_from_master)
{
    // Same master key + same path → same SPHINCS+ key across separate derivations
    CExtKey master;
    CKey seed_key;
    seed_key.MakeNewKey(true);
    master.SetSeed(std::as_bytes(std::span{seed_key.data(), 32}));

    std::vector<uint32_t> path = {0x8000018B, 0x80000000, 0x80000000};

    // Derive SPHINCS+ key directly (no wallet) — twice
    SphincsKey key1 = SphincsKey::DeriveFromMaster(master, path);
    SphincsKey key2 = SphincsKey::DeriveFromMaster(master, path);

    BOOST_CHECK(key1.IsValid());
    BOOST_CHECK(key2.IsValid());
    BOOST_CHECK(std::memcmp(key1.PubkeyData(), key2.PubkeyData(), SphincsKey::PUBLIC_SIZE) == 0);
    BOOST_CHECK(std::memcmp(key1.SecretData(), key2.SecretData(), SphincsKey::SECRET_SIZE) == 0);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
