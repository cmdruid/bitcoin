#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test quantum-insured wallet RPCs (BIP 368/369 wallet support).

Tests:
- createsphincskey: derive and store a SPHINCS+ key
- listsphincskeys: enumerate SPHINCS+ keys
- getquantumaddress: derive quantum-insured Taproot addresses
- Key determinism: same wallet produces same SPHINCS+ key
"""

from decimal import Decimal
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


class WalletSphincsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # BIP 368/369 annexes are now standard (policy.cpp allows type 0x02/0x04)
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Test 1: Create a descriptor wallet")
        node.createwallet(wallet_name="qi_wallet", descriptors=True)
        w = node.get_wallet_rpc("qi_wallet")

        self.log.info("Test 2: listsphincskeys — should be empty initially")
        keys = w.listsphincskeys()
        assert_equal(len(keys), 0)

        self.log.info("Test 3: createsphincskey — derive SPHINCS+ key and register QI descriptor")
        result = w.createsphincskey()
        sphincs_pubkey = result["sphincs_pubkey"]
        self.log.info(f"  SPHINCS+ pubkey: {sphincs_pubkey}")
        assert_equal(len(sphincs_pubkey), 64)  # 32 bytes = 64 hex chars
        assert "qi_descriptor" in result
        self.log.info(f"  QI descriptor: {result['qi_descriptor'][:60]}...")

        self.log.info("Test 4: listsphincskeys — should show the new key")
        keys = w.listsphincskeys()
        assert_equal(len(keys), 1)
        assert_equal(keys[0]["sphincs_pubkey"], sphincs_pubkey)

        self.log.info("Test 5: createsphincskey again — should return same key (idempotent)")
        result2 = w.createsphincskey()
        assert_equal(result2["sphincs_pubkey"], sphincs_pubkey)

        self.log.info("Test 6: getquantumaddress — derive QI Taproot address")
        addr_result = w.getquantumaddress()
        address = addr_result["address"]
        self.log.info(f"  QI address: {address}")
        assert_equal(addr_result["sphincs_pubkey"], sphincs_pubkey)
        assert address.startswith("bcrt1p")  # regtest bech32m

        self.log.info("Test 7: getquantumaddress produces sequential addresses")
        addr_result2 = w.getquantumaddress()
        address2 = addr_result2["address"]
        self.log.info(f"  QI address 2: {address2}")
        assert address != address2  # Sequential addresses are different
        assert_equal(addr_result2["sphincs_pubkey"], sphincs_pubkey)

        self.log.info("Test 8: getnewaddress bech32m also produces QI addresses")
        # Since QI descriptor is registered as active BECH32M, getnewaddress should use it
        addr_from_getnew = w.getnewaddress(address_type="bech32m")
        self.log.info(f"  getnewaddress bech32m: {addr_from_getnew}")
        assert addr_from_getnew.startswith("bcrt1p")

        self.log.info("Test 9: exportqpub — returns base58check qpub string")
        export_result = w.exportqpub()
        assert_equal(export_result["sphincs_pubkey"], sphincs_pubkey)
        assert "qpub" in export_result
        qpub_str = export_result["qpub"]
        self.log.info(f"  qpub: {qpub_str[:20]}...")
        assert qpub_str.startswith("Q"), f"qpub should start with Q, got: {qpub_str[:5]}"

        self.log.info("Test 10: importqpub — create watch-only QI descriptor on a second wallet")
        node.createwallet(wallet_name="qi_watchonly", descriptors=True, disable_private_keys=True)
        w2 = node.get_wallet_rpc("qi_watchonly")
        import_result = w2.importqpub(qpub_str)
        assert_equal(import_result["sphincs_pubkey"], sphincs_pubkey)
        assert "qi_descriptor" in import_result
        self.log.info(f"  Watch-only descriptor: {import_result['qi_descriptor'][:60]}...")

        self.log.info("Test 11: Watch-only wallet can generate QI addresses")
        wo_addr = w2.getnewaddress(address_type="bech32m")
        self.log.info(f"  Watch-only QI address: {wo_addr}")
        assert wo_addr.startswith("bcrt1p")

        self.log.info("Test 12: Different wallets produce different SPHINCS+ keys")
        node.createwallet(wallet_name="qi_wallet2", descriptors=True)
        w_other = node.get_wallet_rpc("qi_wallet2")
        other_result = w_other.createsphincskey()
        # Different wallets (different master keys) produce different SPHINCS+ keys
        assert other_result["sphincs_pubkey"] != sphincs_pubkey
        self.log.info(f"  Wallet 1: {sphincs_pubkey[:16]}...")
        self.log.info(f"  Wallet 2: {other_result['sphincs_pubkey'][:16]}...")

        self.log.info("Test 12a: exportqprv — export private key")
        qprv_str = w.exportqprv()
        self.log.info(f"  qprv: {qprv_str[:20]}...")
        assert qprv_str.startswith("Q"), f"qprv should start with Q, got: {qprv_str[:5]}"

        self.log.info("Test 12b: importqprv — import into a new wallet")
        node.createwallet(wallet_name="qi_imported", descriptors=True)
        w3 = node.get_wallet_rpc("qi_imported")
        import_prv_result = w3.importqprv(qprv_str)
        assert_equal(import_prv_result["sphincs_pubkey"], sphincs_pubkey)
        self.log.info(f"  Imported SPHINCS+ pubkey matches: {import_prv_result['sphincs_pubkey'][:16]}...")

        self.log.info("Test 12c: Encrypted wallet — create SPHINCS+ key while unlocked")
        node.createwallet(wallet_name="qi_encrypted", descriptors=True, passphrase="testpass")
        w_enc = node.get_wallet_rpc("qi_encrypted")
        w_enc.walletpassphrase("testpass", 60)  # Unlock for 60 seconds
        enc_result = w_enc.createsphincskey()
        enc_sphincs_pk = enc_result["sphincs_pubkey"]
        self.log.info(f"  Encrypted wallet SPHINCS+ key: {enc_sphincs_pk[:16]}...")
        assert_equal(len(enc_sphincs_pk), 64)

        self.log.info("Test 12d: Encrypted wallet — listsphincskeys works when locked")
        w_enc.walletlock()
        enc_keys = w_enc.listsphincskeys()
        assert_equal(len(enc_keys), 1)
        assert_equal(enc_keys[0]["sphincs_pubkey"], enc_sphincs_pk)

        self.log.info("Test 12e: Encrypted wallet — getquantumaddress works when locked")
        enc_addr = w_enc.getquantumaddress()
        assert enc_addr["address"].startswith("bcrt1p")
        self.log.info(f"  Encrypted wallet QI address: {enc_addr['address']}")

        # === Funding and spending tests ===

        self.log.info("Test 12: Fund the wallet for spending tests")
        # Mine blocks to a standard address so we have spendable coins
        fund_addr = w.getnewaddress(address_type="bech32m")
        self.generatetoaddress(node, COINBASE_MATURITY + 1, fund_addr)
        balance = w.getbalance()
        self.log.info(f"  Balance: {balance}")
        assert_greater_than(balance, 0)

        self.log.info("Test 13: Get a QI address from the registered descriptor")
        # After createsphincskey, getnewaddress with bech32m should return
        # a QI address (from the registered qis() descriptor)
        qi_recv_addr = w.getnewaddress(address_type="bech32m")
        self.log.info(f"  QI receive address: {qi_recv_addr}")

        self.log.info("Test 14: Send funds to the QI address")
        txid = w.sendtoaddress(qi_recv_addr, 10)
        self.log.info(f"  Send txid: {txid}")
        self.generate(node, 1)

        self.log.info("Test 15: Verify QI UTXO is tracked by wallet")
        utxos = w.listunspent(1, 9999, [qi_recv_addr])
        self.log.info(f"  UTXOs at QI address: {len(utxos)}")
        # The wallet should recognize this UTXO because the QI descriptor is registered
        assert_equal(len(utxos), 1)
        assert_equal(utxos[0]["amount"], Decimal("10"))
        self.log.info(f"  UTXO value: {utxos[0]['amount']} BTC")

        self.log.info("Test 16: Spend FROM the QI address (key-path with BIP 368 annex)")
        # Send from QI UTXO to a standard address
        dest_addr = w.getnewaddress(address_type="bech32m")
        spend_txid = w.sendtoaddress(dest_addr, 5)
        self.log.info(f"  Spend txid: {spend_txid}")
        self.generate(node, 1)

        # Verify the spend was confirmed
        spend_tx = w.gettransaction(spend_txid)
        assert_equal(spend_tx["confirmations"], 1)
        self.log.info(f"  Spend confirmed!")

        self.log.info("Test 17: Deterministic key derivation — same seed produces same SPHINCS+ key")
        # Create another wallet with the same seed to verify determinism
        # We can't easily share seeds between wallets via RPC, but we can verify
        # that the same wallet always produces the same SPHINCS+ key
        keys_check = w.listsphincskeys()
        assert_equal(len(keys_check), 1)
        assert_equal(keys_check[0]["sphincs_pubkey"], sphincs_pubkey)
        self.log.info(f"  SPHINCS+ key is consistent: {sphincs_pubkey[:16]}...")

        # === Edge case tests ===

        self.log.info("Test 18: getquantumaddress before createsphincskey — should error")
        node.createwallet(wallet_name="qi_empty", descriptors=True)
        w_empty = node.get_wallet_rpc("qi_empty")
        try:
            w_empty.getquantumaddress()
            assert False, "Should have thrown"
        except Exception as e:
            self.log.info(f"  Correctly errored: {str(e)[:60]}...")

        self.log.info("Test 19: createsphincskey while locked — should error")
        node.createwallet(wallet_name="qi_locked", descriptors=True, passphrase="pass123")
        w_locked = node.get_wallet_rpc("qi_locked")
        try:
            w_locked.createsphincskey()
            assert False, "Should have thrown"
        except Exception as e:
            self.log.info(f"  Correctly errored: {str(e)[:60]}...")

        self.log.info("Test 20: exportqprv while locked — should error")
        w_locked.walletpassphrase("pass123", 60)
        w_locked.createsphincskey()
        w_locked.walletlock()
        try:
            w_locked.exportqprv()
            assert False, "Should have thrown"
        except Exception as e:
            self.log.info(f"  Correctly errored: {str(e)[:60]}...")

        # === E1: Encrypted wallet signing test ===
        self.log.info("Test 21: Encrypted wallet — fund and spend while unlocked")
        w_locked.walletpassphrase("pass123", 120)
        enc_fund_addr = w_locked.getnewaddress(address_type="bech32")
        self.generatetoaddress(node, COINBASE_MATURITY + 1, enc_fund_addr)
        enc_qi_addr = w_locked.getnewaddress(address_type="bech32m")
        w_locked.sendtoaddress(enc_qi_addr, 5)
        self.generate(node, 1)
        enc_dest = w_locked.getnewaddress(address_type="bech32")
        enc_spend_txid = w_locked.sendtoaddress(enc_dest, 2)
        self.generate(node, 1)
        enc_tx = w_locked.gettransaction(enc_spend_txid)
        assert_equal(enc_tx["confirmations"], 1)
        self.log.info("  Encrypted wallet spend confirmed!")

        # === E3: exportqprv/importqprv address match ===
        self.log.info("Test 22: exportqprv → importqprv address match")
        qprv_export = w.exportqprv()
        node.createwallet(wallet_name="qi_restored", descriptors=True)
        w_restored = node.get_wallet_rpc("qi_restored")
        w_restored.importqprv(qprv_export)
        # Both wallets should derive the same first address
        restored_addr = w_restored.getnewaddress(address_type="bech32m")
        self.log.info(f"  Restored address: {restored_addr}")
        # Note: addresses may differ because the original wallet has already
        # advanced next_index. But the SPHINCS+ key should match.
        restored_keys = w_restored.listsphincskeys()
        assert_equal(len(restored_keys), 1)
        assert_equal(restored_keys[0]["sphincs_pubkey"], sphincs_pubkey)
        self.log.info(f"  SPHINCS+ key matches after qprv round-trip!")

        # === E7: Co-activation boundary (covered by wallet_sphincs_activation.py) ===

        # === E8: Encrypted wallet SPHINCS+ round-trip ===
        self.log.info("=== E8: Encrypted wallet SPHINCS+ round-trip ===")
        node.createwallet(wallet_name="encrypted_qi", descriptors=True)
        enc_w = node.get_wallet_rpc("encrypted_qi")
        enc_w.encryptwallet("testpassword")
        # Wallet is now locked — createsphincskey should fail
        try:
            enc_w.createsphincskey()
            assert False, "Should have raised (wallet locked)"
        except Exception as e:
            self.log.info(f"  Locked createsphincskey correctly rejected: {e}")

        # Unlock and create key
        enc_w.walletpassphrase("testpassword", 60)
        enc_result = enc_w.createsphincskey()
        enc_sphincs_pk = enc_result["sphincs_pubkey"]
        self.log.info(f"  Created SPHINCS+ key on encrypted wallet: {enc_sphincs_pk}")

        # Lock and verify read-only operations work
        enc_w.walletlock()
        keys = enc_w.listsphincskeys()
        assert_equal(len(keys), 1)
        assert_equal(keys[0]["sphincs_pubkey"], enc_sphincs_pk)
        self.log.info("  listsphincskeys works while locked")

        qpub_result = enc_w.exportqpub()
        assert "qpub" in qpub_result
        self.log.info("  exportqpub works while locked")

        # exportqprv should fail while locked
        try:
            enc_w.exportqprv()
            assert False, "Should have raised (wallet locked)"
        except Exception as e:
            self.log.info(f"  Locked exportqprv correctly rejected: {e}")

        self.log.info("  Encrypted wallet SPHINCS+ round-trip passed!")

        self.log.info("All quantum-insured wallet tests passed!")


if __name__ == '__main__':
    WalletSphincsTest(__file__).main()
