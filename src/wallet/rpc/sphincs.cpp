// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>

#include <chainparams.h>
#include <consensus/amount.h>
#include <util/moneystr.h>
#include <key_io.h>
#include <outputtype.h>
#include <psbt.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <wallet/coincontrol.h>
#include <wallet/qextkey.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/sphincskeys.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <univalue.h>

#include <cstring>

namespace wallet {

/** Store a SPHINCS+ key on a descriptor SPKM, handling encryption if needed.
 *  Writes to the DB and loads into the SPKM's in-memory state.
 *  IV for encryption is Hash(desc_id || pubkey) for per-descriptor uniqueness.
 */
static void StoreSphincsKeyOnSPKM(CWallet& wallet, WalletBatch& batch,
                                   DescriptorScriptPubKeyMan& spkm,
                                   std::span<const unsigned char> secret,
                                   const std::array<unsigned char, 32>& pubkey)
{
    std::span<const unsigned char> pubkey_span{pubkey.data(), 32};

    if (wallet.HasEncryptionKeys()) {
        CKeyingMaterial secret_material{secret.begin(), secret.end()};
        std::vector<unsigned char> crypted;
        uint256 iv = (HashWriter{} << spkm.GetID() << MakeByteSpan(pubkey)).GetHash();
        if (!wallet.WithEncryptionKey([&](const CKeyingMaterial& enc_key) {
            return EncryptSecret(enc_key, secret_material, iv, crypted);
        })) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to encrypt SPHINCS+ key.");
        }
        batch.WriteCryptedSphincsKey(spkm.GetID(), pubkey, crypted);
        spkm.LoadCryptedSphincsKey(pubkey_span, crypted);
    } else {
        std::array<unsigned char, 64> sk_arr;
        std::copy(secret.begin(), secret.end(), sk_arr.begin());
        batch.WriteSphincsKey(spkm.GetID(), pubkey, sk_arr);
        spkm.LoadSphincsKey(pubkey_span, secret);
    }
}

RPCMethod createsphincskey()
{
    return RPCMethod{
        "createsphincskey",
        "Derive and store a SPHINCS+ keypair for quantum-insured spending.\n"
        "The key is derived deterministically from the wallet's master key using\n"
        "HMAC-SHA512(\"Sphincs seed\", master_ext_privkey || account_path).\n"
        "One SPHINCS+ key is created per account.\n",
        {
            {"account_index", RPCArg::Type::NUM, RPCArg::Default{0}, "The account index (m/395'/0'/N')."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "sphincs_pubkey", "The 32-byte SPHINCS+ public key"},
                {RPCResult::Type::STR, "qi_descriptor", "The quantum-insured Taproot descriptor registered in the wallet"},
            }
        },
        RPCExamples{
            HelpExampleCli("createsphincskey", "")
            + HelpExampleCli("createsphincskey", "1")
            + HelpExampleRpc("createsphincskey", "0")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(*pwallet);

            unsigned int account_index = 0;
            if (!request.params[0].isNull()) {
                account_index = request.params[0].getInt<unsigned int>();
            }
            if (account_index >= 0x80000000) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "account_index must be less than 2^31");
            }

            // Build the BIP 395 account path: m/395'/coin_type'/account'
            // coin_type: 0' for mainnet, 1' for testnet/signet/regtest (per SLIP-44)
            uint32_t coin_type = (Params().GetChainType() == ChainType::MAIN) ?
                0x80000000 : 0x80000001;
            std::vector<uint32_t> account_path = {
                0x8000018B,                         // 395' (purpose)
                coin_type,                          // coin_type'
                0x80000000 + account_index          // account'
            };

            // Find the master CExtKey and a descriptor manager to store the
            // SPHINCS+ key on. Following the gethdkeys RPC pattern:
            // 1. Get xpubs (with chain codes) from descriptor via GetPubKeys()
            // 2. Get private key via GetKey()
            // 3. Reconstruct CExtKey via CExtKey(xpub, key)
            DescriptorScriptPubKeyMan* target_spk_man = nullptr;
            CExtKey master_ext;
            bool found_master = false;

            for (auto* mgr : pwallet->GetAllScriptPubKeyMans()) {
                auto* desc_mgr = dynamic_cast<DescriptorScriptPubKeyMan*>(mgr);
                if (!desc_mgr) continue;

                // If this manager already has a SPHINCS+ key, return it
                if (desc_mgr->HasSphincsKey()) {
                    auto pk = desc_mgr->GetSphincsPubkey();
                    if (pk) {
                        std::string desc_str;
                        {
                            LOCK(desc_mgr->cs_desc_man);
                            desc_mgr->GetDescriptorString(desc_str, false);
                        }
                        UniValue result(UniValue::VOBJ);
                        result.pushKV("sphincs_pubkey", HexStr(*pk));
                        result.pushKV("qi_descriptor", desc_str);
                        return result;
                    }
                }

                if (!found_master) {
                    LOCK(desc_mgr->cs_desc_man);
                    WalletDescriptor wd = desc_mgr->GetWalletDescriptor();
                    if (!wd.descriptor) continue;

                    // Only attach SPHINCS+ key to Taproot (bech32m) descriptors
                    auto out_type = wd.descriptor->GetOutputType();
                    if (!out_type || *out_type != OutputType::BECH32M) continue;

                    // Extract xpubs (which include chain codes)
                    std::set<CPubKey> pubkeys;
                    std::set<CExtPubKey> xpubs;
                    wd.descriptor->GetPubKeys(pubkeys, xpubs);

                    for (const CExtPubKey& xpub : xpubs) {
                        // Try to get the corresponding private key
                        if (auto key = desc_mgr->GetKey(xpub.pubkey.GetID())) {
                            // Reconstruct full CExtKey (private key + chain code)
                            master_ext = CExtKey(xpub, *key);
                            target_spk_man = desc_mgr;
                            found_master = true;
                            break;
                        }
                    }
                }
            }

            if (!found_master || !target_spk_man) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Could not find master key in wallet. Ensure wallet has private keys and is unlocked.");
            }

            // Derive the SPHINCS+ key (stored on QI SPKMs below, not on the old tr() SPKM)
            SphincsKey sphincs_key = SphincsKey::DeriveFromMaster(master_ext, account_path);
            std::array<unsigned char, 32> sphincs_pk;
            std::copy(sphincs_key.PubkeyData(), sphincs_key.PubkeyData() + 32, sphincs_pk.begin());

            // Register a QI descriptor so the wallet tracks quantum-insured UTXOs.
            // Derive account-level extended key at m/395'/0'/account'
            CExtKey purpose_key, cointype_key, account_ext;
            if (!master_ext.Derive(purpose_key, account_path[0])) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive purpose key.");
            }
            if (!purpose_key.Derive(cointype_key, account_path[1])) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive coin type key.");
            }
            if (!cointype_key.Derive(account_ext, account_path[2])) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive account key.");
            }

            // Build QI descriptor using qr() format
            QExtPubKey account_qpub;
            account_qpub.extpub = account_ext.Neuter();
            account_qpub.sphincs_pubkey = sphincs_pk;
            std::string qpub_str = EncodeQExtPubKey(account_qpub);
            std::string sphincs_hex = HexStr(sphincs_pk);
            std::string qi_desc_str = "qr(" + qpub_str + "/0/*)";

            // Parse the descriptor
            FlatSigningProvider desc_keys;
            std::string desc_error;
            auto parsed_descs = Parse(qi_desc_str, desc_keys, desc_error, /*require_checksum=*/false);
            if (parsed_descs.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to parse QI descriptor: %s", desc_error));
            }

            // Add the account private key so the wallet can sign
            desc_keys.keys[account_ext.key.GetPubKey().GetID()] = account_ext.key;

            // Import the descriptor into the wallet
            WalletDescriptor w_desc(std::move(parsed_descs[0]), GetTime(), 0, 1000, 0);
            auto add_result = pwallet->AddWalletDescriptor(w_desc, desc_keys, "", /*internal=*/false);
            if (!add_result) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to add QI descriptor: %s", util::ErrorString(add_result).original));
            }

            // Store the SPHINCS+ key on the new QI SPKM
            auto& qi_spk_man = add_result->get();
            {
                WalletBatch qi_batch(pwallet->GetDatabase());
                StoreSphincsKeyOnSPKM(*pwallet, qi_batch, qi_spk_man,
                    {sphincs_key.SecretData(), 64}, sphincs_pk);
            }

            // Register as active for BECH32M (Taproot) — external (receiving)
            auto qi_spk_man_id = qi_spk_man.GetID();
            pwallet->AddActiveScriptPubKeyMan(qi_spk_man_id, OutputType::BECH32M, /*internal=*/false);

            // Also register an internal (change) QI descriptor with /1/* path
            std::string qi_int_desc_str = "qr(" + qpub_str + "/1/*)";
            FlatSigningProvider int_desc_keys;
            std::string int_desc_error;
            auto int_parsed = Parse(qi_int_desc_str, int_desc_keys, int_desc_error, /*require_checksum=*/false);
            if (!int_parsed.empty()) {
                int_desc_keys.keys[account_ext.key.GetPubKey().GetID()] = account_ext.key;
                WalletDescriptor int_w_desc(std::move(int_parsed[0]), GetTime(), 0, 1000, 0);
                auto int_result = pwallet->AddWalletDescriptor(int_w_desc, int_desc_keys, "", /*internal=*/true);
                if (int_result) {
                    auto& int_spk_man = int_result->get();
                    WalletBatch int_qi_batch(pwallet->GetDatabase());
                    StoreSphincsKeyOnSPKM(*pwallet, int_qi_batch, int_spk_man,
                        {sphincs_key.SecretData(), 64}, sphincs_pk);
                    pwallet->AddActiveScriptPubKeyMan(int_spk_man.GetID(), OutputType::BECH32M, /*internal=*/true);
                }
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("sphincs_pubkey", sphincs_hex);
            result.pushKV("qi_descriptor", qi_desc_str);
            return result;
        },
    };
}

RPCMethod getquantumaddress()
{
    return RPCMethod{
        "getquantumaddress",
        "Returns a new quantum-insured Taproot address.\n"
        "Uses the registered QI descriptor (created by createsphincskey) to generate\n"
        "the next address in the keypool. Equivalent to getnewaddress with bech32m\n"
        "when a QI descriptor is active.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "The quantum-insured Taproot address (bech32m)"},
                {RPCResult::Type::STR_HEX, "sphincs_pubkey", "The 32-byte SPHINCS+ public key used in the hybrid tapleaf"},
            }
        },
        RPCExamples{
            HelpExampleCli("getquantumaddress", "")
            + HelpExampleRpc("getquantumaddress", "")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            // Use the registered QI descriptor via GetNewDestination
            // This produces the next address from the active BECH32M descriptor
            auto op_dest = pwallet->GetNewDestination(OutputType::BECH32M, "");
            if (!op_dest) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to generate address: %s", util::ErrorString(op_dest).original));
            }

            // Find the SPHINCS+ pubkey for the result
            std::string sphincs_hex;
            for (auto* mgr : pwallet->GetAllScriptPubKeyMans()) {
                auto* desc_mgr = dynamic_cast<DescriptorScriptPubKeyMan*>(mgr);
                if (desc_mgr && desc_mgr->HasSphincsKey()) {
                    auto pk = desc_mgr->GetSphincsPubkey();
                    if (pk) sphincs_hex = HexStr(*pk);
                    break;
                }
            }

            if (sphincs_hex.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "No SPHINCS+ key found. Run createsphincskey first.");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("address", EncodeDestination(*op_dest));
            result.pushKV("sphincs_pubkey", sphincs_hex);
            return result;
        },
    };
}

RPCMethod exportqpub()
{
    return RPCMethod{
        "exportqpub",
        "Export the quantum-insured extended public key (qpub) for this wallet.\n"
        "The qpub contains the BIP 32 extended public key plus the SPHINCS+ public key,\n"
        "enabling watch-only wallets to derive quantum-insured Taproot addresses.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "qpub", "The base58check-encoded quantum-insured extended public key (Q1...)"},
                {RPCResult::Type::STR_HEX, "sphincs_pubkey", "The 32-byte SPHINCS+ public key"},
                {RPCResult::Type::STR, "descriptor", "The Taproot descriptor"},
            }
        },
        RPCExamples{
            HelpExampleCli("exportqpub", "")
            + HelpExampleRpc("exportqpub", "")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            for (auto* mgr : pwallet->GetAllScriptPubKeyMans()) {
                auto* desc_mgr = dynamic_cast<DescriptorScriptPubKeyMan*>(mgr);
                if (!desc_mgr || !desc_mgr->HasSphincsKey()) continue;

                auto sphincs_pk = desc_mgr->GetSphincsPubkey();
                if (!sphincs_pk) continue;

                LOCK(desc_mgr->cs_desc_man);
                WalletDescriptor wd = desc_mgr->GetWalletDescriptor();
                if (!wd.descriptor) continue;

                // Extract xpubs from descriptor (gethdkeys pattern)
                std::set<CPubKey> pubkeys;
                std::set<CExtPubKey> xpubs;
                wd.descriptor->GetPubKeys(pubkeys, xpubs);

                for (const CExtPubKey& xpub : xpubs) {
                    // Build QExtPubKey
                    QExtPubKey qpub;
                    qpub.extpub = xpub;
                    qpub.sphincs_pubkey = *sphincs_pk;

                    std::string desc_str;
                    desc_mgr->GetDescriptorString(desc_str, false);

                    UniValue result(UniValue::VOBJ);
                    result.pushKV("qpub", EncodeQExtPubKey(qpub));
                    result.pushKV("sphincs_pubkey", HexStr(*sphincs_pk));
                    result.pushKV("descriptor", desc_str);
                    return result;
                }
            }

            throw JSONRPCError(RPC_WALLET_ERROR, "No SPHINCS+ key found in this wallet.");
        },
    };
}

RPCMethod importqpub()
{
    return RPCMethod{
        "importqpub",
        "Import a quantum-insured extended public key (qpub) as a watch-only descriptor.\n"
        "Creates a QI descriptor that tracks quantum-insured Taproot addresses derived from the qpub.\n"
        "The wallet will detect incoming payments to these addresses but cannot spend (watch-only).\n",
        {
            {"qpub", RPCArg::Type::STR, RPCArg::Optional::NO, "The base58check-encoded qpub string (Q1...)."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "sphincs_pubkey", "The 32-byte SPHINCS+ public key"},
                {RPCResult::Type::STR, "qi_descriptor", "The imported QI descriptor"},
                {RPCResult::Type::STR, "address", /*optional=*/true, "The first quantum-insured address"},
            }
        },
        RPCExamples{
            HelpExampleCli("importqpub", "\"Q1...\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            std::string qpub_str = request.params[0].get_str();
            QExtPubKey qpub = DecodeQExtPubKey(qpub_str);
            if (!qpub.extpub.pubkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid qpub string.");
            }

            // Build QI descriptor using qr() format
            std::string sphincs_hex = HexStr(qpub.sphincs_pubkey);
            std::string qi_desc_str = "qr(" + qpub_str + "/0/*)";

            // Parse the descriptor (watch-only — no private keys)
            FlatSigningProvider desc_keys;
            std::string desc_error;
            auto parsed_descs = Parse(qi_desc_str, desc_keys, desc_error, /*require_checksum=*/false);
            if (parsed_descs.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to parse QI descriptor: %s", desc_error));
            }

            // Import as watch-only descriptor (no private keys)
            WalletDescriptor w_desc(std::move(parsed_descs[0]), GetTime(), 0, 1000, 0);
            auto add_result = pwallet->AddWalletDescriptor(w_desc, desc_keys, "", /*internal=*/false);
            if (!add_result) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to import QI descriptor: %s", util::ErrorString(add_result).original));
            }

            // Register as active for BECH32M
            pwallet->AddActiveScriptPubKeyMan(add_result->get().GetID(), OutputType::BECH32M, /*internal=*/false);

            // Derive the first address
            CTxDestination dest = qpub.DeriveAddress(0);

            UniValue result(UniValue::VOBJ);
            result.pushKV("sphincs_pubkey", sphincs_hex);
            result.pushKV("qi_descriptor", qi_desc_str);
            if (!std::holds_alternative<CNoDestination>(dest)) {
                result.pushKV("address", EncodeDestination(dest));
            }
            return result;
        },
    };
}

RPCMethod exportqprv()
{
    return RPCMethod{
        "exportqprv",
        "Export the quantum-insured extended private key (qprv) for this wallet.\n"
        "The qprv contains the BIP 32 extended private key plus the SPHINCS+ secret key.\n"
        "WARNING: This exposes private key material. Handle with care.\n",
        {},
        RPCResult{
            RPCResult::Type::STR, "qprv", "The base58check-encoded quantum-insured extended private key (Q1...)"
        },
        RPCExamples{
            HelpExampleCli("exportqprv", "")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(*pwallet);

            for (auto* mgr : pwallet->GetAllScriptPubKeyMans()) {
                auto* desc_mgr = dynamic_cast<DescriptorScriptPubKeyMan*>(mgr);
                if (!desc_mgr || !desc_mgr->HasSphincsKey()) continue;

                auto sphincs_pk = desc_mgr->GetSphincsPubkey();
                if (!sphincs_pk) continue;

                LOCK(desc_mgr->cs_desc_man);
                WalletDescriptor wd = desc_mgr->GetWalletDescriptor();
                if (!wd.descriptor) continue;

                // Extract xpubs and reconstruct CExtKey (gethdkeys pattern)
                std::set<CPubKey> pubkeys;
                std::set<CExtPubKey> xpubs;
                wd.descriptor->GetPubKeys(pubkeys, xpubs);

                for (const CExtPubKey& xpub : xpubs) {
                    if (auto key = desc_mgr->GetKey(xpub.pubkey.GetID())) {
                        CExtKey ext_key(xpub, *key);

                        // Retrieve the stored SPHINCS+ key (decrypting if needed)
                        auto signing_key = desc_mgr->GetSphincsSigningKey();
                        if (!signing_key || !signing_key->IsValid()) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "SPHINCS+ secret key not available (wallet may be locked).");
                        }
                        QExtKey qkey;
                        qkey.extkey = ext_key;
                        std::memcpy(qkey.sphincs_secret.data(), signing_key->SecretData(), 64);

                        return EncodeQExtKey(qkey);
                    }
                }
            }

            throw JSONRPCError(RPC_WALLET_ERROR, "No SPHINCS+ key found in this wallet.");
        },
    };
}

RPCMethod importqprv()
{
    return RPCMethod{
        "importqprv",
        "Import a quantum-insured extended private key (qprv).\n"
        "Creates a full signing wallet with the QI descriptor.\n",
        {
            {"qprv", RPCArg::Type::STR, RPCArg::Optional::NO, "The base58check-encoded qprv string (Q1...)."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "sphincs_pubkey", "The 32-byte SPHINCS+ public key"},
                {RPCResult::Type::STR, "qi_descriptor", "The imported QI descriptor"},
            }
        },
        RPCExamples{
            HelpExampleCli("importqprv", "\"Q1...\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            std::string qprv_str = request.params[0].get_str();
            QExtKey qkey = DecodeQExtKey(qprv_str);
            if (!qkey.extkey.key.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid qprv string.");
            }

            // Build QI descriptor using qr() format
            QExtPubKey import_qpub = qkey.Neuter();
            std::string import_qpub_str = EncodeQExtPubKey(import_qpub);
            std::string sphincs_hex = HexStr(std::span<const unsigned char>{
                qkey.sphincs_secret.data() + 32, 32});
            std::string qi_desc_str = "qr(" + import_qpub_str + "/0/*)";

            FlatSigningProvider desc_keys;
            std::string desc_error;
            auto parsed_descs = Parse(qi_desc_str, desc_keys, desc_error, /*require_checksum=*/false);
            if (parsed_descs.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to parse QI descriptor: %s", desc_error));
            }

            // Add the private key for signing
            desc_keys.keys[qkey.extkey.key.GetPubKey().GetID()] = qkey.extkey.key;

            WalletDescriptor w_desc(std::move(parsed_descs[0]), GetTime(), 0, 1000, 0);
            auto add_result = pwallet->AddWalletDescriptor(w_desc, desc_keys, "", /*internal=*/false);
            if (!add_result) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to import QI descriptor: %s", util::ErrorString(add_result).original));
            }

            // Store the SPHINCS+ key on the new QI SPKM
            auto& spk_man = add_result->get();
            {
                WalletBatch batch(pwallet->GetDatabase());
                std::array<unsigned char, 32> pk_arr;
                std::copy(qkey.sphincs_secret.data() + 32, qkey.sphincs_secret.data() + 64, pk_arr.begin());
                StoreSphincsKeyOnSPKM(*pwallet, batch, spk_man,
                    {qkey.sphincs_secret.data(), 64}, pk_arr);
            }

            pwallet->AddActiveScriptPubKeyMan(spk_man.GetID(), OutputType::BECH32M, /*internal=*/false);

            UniValue result(UniValue::VOBJ);
            result.pushKV("sphincs_pubkey", sphincs_hex);
            result.pushKV("qi_descriptor", qi_desc_str);
            return result;
        },
    };
}

RPCMethod listsphincskeys()
{
    return RPCMethod{
        "listsphincskeys",
        "List all SPHINCS+ keys associated with this wallet.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "sphincs_pubkey", "The 32-byte SPHINCS+ public key"},
                        {RPCResult::Type::BOOL, "has_private_key", "Whether the private key is available"},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("listsphincskeys", "")
            + HelpExampleRpc("listsphincskeys", "")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            UniValue result(UniValue::VARR);
            std::set<std::string> seen_pubkeys; // deduplicate across SPKMs
            for (auto* mgr : pwallet->GetAllScriptPubKeyMans()) {
                auto* desc_mgr = dynamic_cast<DescriptorScriptPubKeyMan*>(mgr);
                if (desc_mgr && desc_mgr->HasSphincsKey()) {
                    auto sphincs_pk = desc_mgr->GetSphincsPubkey();
                    if (!sphincs_pk) continue;

                    std::string pk_hex = HexStr(*sphincs_pk);
                    if (!seen_pubkeys.insert(pk_hex).second) continue; // skip duplicate

                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("sphincs_pubkey", pk_hex);
                    entry.pushKV("has_private_key", true);
                    result.push_back(std::move(entry));
                }
            }

            return result;
        },
    };
}

RPCMethod sphincsspend()
{
    return RPCMethod{
        "sphincsspend",
        "Spend from a quantum-insured address using the SPHINCS+ emergency script-path.\n"
        "This forces a script-path spend through the hybrid tapleaf, requiring both\n"
        "SPHINCS+ and Schnorr signatures. Use this when key-path spending is compromised\n"
        "by a quantum threat.\n"
        "If amount is omitted, sweeps all available funds (minus fees) to the destination.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination bitcoin address."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "The amount in BTC to send. If omitted, sweeps all funds."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
            }
        },
        RPCExamples{
            HelpExampleCli("sphincsspend", "\"bc1p...\" 1.0")
            + HelpExampleCli("sphincsspend", "\"bc1p...\"")
            + HelpExampleRpc("sphincsspend", "\"bc1p...\", 1.0")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            CWallet& wallet{*pwallet};
            wallet.BlockUntilSyncedToCurrentChain();

            LOCK(wallet.cs_wallet);
            EnsureWalletIsUnlocked(wallet);

            // Parse destination address
            CTxDestination dest = DecodeDestination(request.params[0].get_str());
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }

            // Build set of QI SPKM pointers for quick lookup
            std::set<ScriptPubKeyMan*> qi_spkms;
            for (ScriptPubKeyMan* spk_man : wallet.GetAllScriptPubKeyMans()) {
                auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
                if (desc_spkm && desc_spkm->HasSphincsKey()) {
                    qi_spkms.insert(spk_man);
                }
            }
            if (qi_spkms.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    "No quantum-insured descriptor found. Run createsphincskey first.");
            }

            struct QICoin {
                COutPoint outpoint;
                CAmount value;
            };

            // Collect QI UTXOs. A UTXO is QI if any of its managing SPKMs has a
            // SPHINCS+ key. For non-sweep spends we intentionally do not select
            // every QI coin up front, because each additional selected input
            // requires another large SPHINCS+ script-path signature.
            std::vector<QICoin> qi_coins;
            CAmount qi_total = 0;

            for (const auto& [txid, wtx] : wallet.mapWallet) {
                for (unsigned int n = 0; n < wtx.tx->vout.size(); ++n) {
                    const CTxOut& out = wtx.tx->vout[n];
                    COutPoint outpoint(txid, n);
                    if (!wallet.IsMine(outpoint) || wallet.IsSpent(outpoint)) continue;

                    // Check if this scriptPubKey is managed by a QI SPKM
                    auto spk_mans = wallet.GetScriptPubKeyMans(out.scriptPubKey);
                    bool is_qi = false;
                    for (auto* spk_man : spk_mans) {
                        if (qi_spkms.count(spk_man)) {
                            is_qi = true;
                            break;
                        }
                    }
                    if (is_qi) {
                        qi_coins.push_back({outpoint, out.nValue});
                        if (qi_total > MAX_MONEY - out.nValue) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "QI UTXO sum exceeds maximum money");
                        }
                        qi_total += out.nValue;
                    }
                }
            }

            if (qi_total == 0) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    "No quantum-insured UTXOs available");
            }

            // Determine amount (sweep mode if omitted)
            bool sweep = request.params[1].isNull();
            CAmount amount = 0;
            bool subtract_fee = false;

            if (sweep) {
                amount = qi_total;
                subtract_fee = true;
            } else {
                amount = AmountFromValue(request.params[1]);
                if (amount > qi_total) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                        strprintf("Requested %s but only %s available in quantum-insured UTXOs",
                                  FormatMoney(amount), FormatMoney(qi_total)));
                }
            }

            // Build recipients
            std::vector<CRecipient> recipients;
            recipients.push_back({dest, amount, subtract_fee});

            CCoinControl coin_control;
            coin_control.m_allow_other_inputs = false;

            std::optional<CreatedTransactionResult> txr;
            bilingual_str create_error;
            size_t selected_qi_inputs = 0;

            auto try_create_tx = [&](const CCoinControl& control) {
                auto attempt = CreateTransaction(wallet, recipients, /*change_pos=*/std::nullopt, control, /*sign=*/false);
                if (!attempt) {
                    create_error = util::ErrorString(attempt);
                    return false;
                }
                txr.emplace(std::move(*attempt));
                return true;
            };

            if (sweep) {
                for (const auto& coin : qi_coins) {
                    coin_control.Select(coin.outpoint);
                }
                selected_qi_inputs = qi_coins.size();
                if (!try_create_tx(coin_control)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, create_error.original);
                }
            } else {
                // Prefer larger QI coins first to minimize the number of
                // SPHINCS+ inputs and keep the emergency spend responsive.
                std::stable_sort(qi_coins.begin(), qi_coins.end(), [](const QICoin& a, const QICoin& b) {
                    return a.value > b.value;
                });

                CAmount selected_total = 0;
                for (const auto& coin : qi_coins) {
                    coin_control.Select(coin.outpoint);
                    selected_total += coin.value;
                    ++selected_qi_inputs;

                    if (selected_total < amount) continue;
                    if (try_create_tx(coin_control)) break;
                }

                if (!txr) {
                    throw JSONRPCError(RPC_WALLET_ERROR, create_error.original);
                }
            }

            wallet.WalletLogPrintf("sphincsspend selected %u/%u QI inputs (%s requested, %s available)\n",
                                   selected_qi_inputs, qi_coins.size(), FormatMoney(amount), FormatMoney(qi_total));

            // Build a PSBT from the unsigned transaction
            PartiallySignedTransaction psbtx(CMutableTransaction(*txr->tx));

            // Sign with SPHINCS+ emergency mode
            bool complete = false;
            const auto fill_err{wallet.FillPSBT(psbtx, complete, /*sighash_type=*/std::nullopt,
                                                 /*sign=*/true, /*bip32derivs=*/true,
                                                 /*n_signed=*/nullptr, /*finalize=*/true,
                                                 /*sphincs_emergency=*/true)};
            if (fill_err) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign PSBT with SPHINCS+ emergency mode");
            }

            if (!complete) {
                throw JSONRPCError(RPC_WALLET_ERROR, "SPHINCS+ emergency signing did not produce a complete transaction. "
                                   "Ensure the wallet holds a SPHINCS+ key and the inputs are quantum-insured outputs.");
            }

            // Extract the final transaction
            CMutableTransaction mtx;
            if (!FinalizeAndExtractPSBT(psbtx, mtx)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to finalize SPHINCS+ emergency transaction");
            }

            // Broadcast
            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            wallet.CommitTransaction(tx_ref, {}, {});

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx_ref->GetHash().GetHex());
            return result;
        },
    };
}

} // namespace wallet
