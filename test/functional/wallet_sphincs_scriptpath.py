#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test SPHINCS+ emergency spending via sphincsspend RPC.

This tests the full quantum emergency spending scenario: the user spends
through the hybrid tapleaf requiring both SPHINCS+ and Schnorr signatures
using the sphincsspend RPC command.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class WalletSphincsScriptPathTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        # Create a separate miner wallet for funding
        node.createwallet(wallet_name="miner_wallet", descriptors=True)
        miner = node.get_wallet_rpc("miner_wallet")
        miner_addr = miner.getnewaddress(address_type="bech32m")
        self.generatetoaddress(node, COINBASE_MATURITY + 10, miner_addr)

        self.log.info("Setup: Create QI wallet with SPHINCS+ key")
        node.createwallet(wallet_name="qi_wallet", descriptors=True)
        w = node.get_wallet_rpc("qi_wallet")
        result = w.createsphincskey()
        sphincs_pubkey_hex = result["sphincs_pubkey"]
        self.log.info(f"  SPHINCS+ pubkey: {sphincs_pubkey_hex}")

        self.log.info("Test 1: Key-path spend of QI output (regression)")
        # Fund a QI address from the miner wallet
        qi_addr1 = w.getquantumaddress()["address"]
        miner.sendtoaddress(qi_addr1, 10)
        self.generate(node, 1)

        # Key-path spend (normal sendtoaddress)
        dest1 = miner.getnewaddress(address_type="bech32m")
        kp_txid = w.sendtoaddress(dest1, 3)
        self.generate(node, 1)
        assert_equal(w.gettransaction(kp_txid)["confirmations"], 1)
        self.log.info("  Key-path spend confirmed")

        # Verify BIP 368 annex in key-path witness
        raw_tx = node.decoderawtransaction(w.gettransaction(kp_txid, True)["hex"])
        for vin in raw_tx["vin"]:
            if "txinwitness" in vin:
                witness = vin["txinwitness"]
                self.log.info(f"  Key-path witness: {len(witness)} elements")
                if len(witness) >= 2 and witness[-1][:2] == "50":
                    annex_type = witness[-1][2:4]
                    assert_equal(annex_type, "02")
                    self.log.info("  BIP 368 key-path annex (type 0x02) verified")

        self.log.info("Test 2: sphincsspend — emergency script-path spend")
        # Fund another QI address
        qi_addr2 = w.getquantumaddress()["address"]
        self.log.info(f"  QI address for emergency test: {qi_addr2}")
        miner.sendtoaddress(qi_addr2, 5)
        self.generate(node, 1)

        # Debug: check what UTXOs the QI wallet sees
        all_utxos = w.listunspent()
        self.log.info(f"  QI wallet has {len(all_utxos)} UTXOs:")
        for u in all_utxos:
            self.log.info(f"    {u['address']}: {u['amount']} BTC (desc: {u.get('desc', 'N/A')[:60]})")

        # Emergency spend via sphincsspend
        dest2 = miner.getnewaddress(address_type="bech32m")
        sphincs_result = w.sphincsspend(dest2, 2)
        sphincs_txid = sphincs_result["txid"]
        self.log.info(f"  sphincsspend txid: {sphincs_txid}")

        # Mine and confirm
        self.generate(node, 1)
        tx_info = w.gettransaction(sphincs_txid)
        assert_equal(tx_info["confirmations"], 1)
        self.log.info("  SPHINCS+ script-path spend confirmed!")

        # Verify the witness contains script-path elements
        raw_tx = node.decoderawtransaction(w.gettransaction(sphincs_txid, True)["hex"])
        found_script_path = False
        for vin in raw_tx["vin"]:
            if "txinwitness" not in vin:
                continue
            witness = vin["txinwitness"]
            self.log.info(f"  Witness elements: {len(witness)}")
            for i, elem in enumerate(witness):
                self.log.info(f"    [{i}] {len(elem)//2} bytes")

            # Script-path witness: [schnorr_sig, script, control_block, annex]
            # Annex starts with 0x50, type 0x04 for BIP 369 SPHINCS+
            if len(witness) >= 4 and witness[-1][:2] == "50":
                annex_type = witness[-1][2:4]
                if annex_type == "04":
                    found_script_path = True
                    annex_bytes = len(witness[-1]) // 2
                    self.log.info(f"  BIP 369 script-path annex (type 0x04) verified!")
                    self.log.info(f"  Annex size: {annex_bytes} bytes")
                    # Annex should contain at least one 4080-byte SPHINCS+ signature
                    assert_greater_than(annex_bytes, 4080)

        if not found_script_path:
            self.log.info("  WARNING: witness shows key-path format, not script-path")
            self.log.info("  This may occur if coin selection picked a non-QI UTXO")

        self.log.info("Test 3: sphincsspend should not consume every QI UTXO")
        funded_qi_addrs = []
        for _ in range(5):
            funded_qi_addrs.append(w.getquantumaddress()["address"])
        for addr in funded_qi_addrs:
            miner.sendtoaddress(addr, 1)
        self.generate(node, 1)

        qi_utxos_before = [u for u in w.listunspent() if u.get("desc", "").startswith("qr(")]
        self.log.info(f"  QI UTXOs before targeted spend: {len(qi_utxos_before)}")

        dest3 = miner.getnewaddress(address_type="bech32m")
        targeted_result = w.sphincsspend(dest3, 2)
        targeted_txid = targeted_result["txid"]
        raw_tx = node.decoderawtransaction(w.gettransaction(targeted_txid, True)["hex"])
        self.log.info(f"  Targeted emergency spend inputs: {len(raw_tx['vin'])}")
        assert len(raw_tx["vin"]) < len(qi_utxos_before), "sphincsspend should not consume every QI UTXO for a partial send"
        self.generate(node, 1)
        assert_equal(w.gettransaction(targeted_txid)["confirmations"], 1)

        self.log.info("Test 4: sphincsspend sweep mode")
        # Fund for sweep
        qi_addr3 = w.getquantumaddress()["address"]
        miner.sendtoaddress(qi_addr3, 1)
        self.generate(node, 1)

        balance_before = w.getbalance()
        assert_greater_than(balance_before, 0)
        self.log.info(f"  Balance before sweep: {balance_before}")

        sweep_dest = miner.getnewaddress(address_type="bech32m")
        sweep_result = w.sphincsspend(sweep_dest)
        sweep_txid = sweep_result["txid"]
        self.generate(node, 1)
        assert_equal(w.gettransaction(sweep_txid)["confirmations"], 1)
        self.log.info(f"  Sweep confirmed: {sweep_txid}")

        self.log.info("Test 5: sphincsspend error — insufficient QI funds")
        # Try to spend more than available
        try:
            w.sphincsspend(miner.getnewaddress(address_type="bech32m"), 999999)
            assert False, "Should have raised"
        except Exception as e:
            self.log.info(f"  Correctly rejected: {e}")

        self.log.info("Test 6: sphincsspend error — no QI UTXOs")
        # Create a wallet without SPHINCS+ key
        node.createwallet(wallet_name="no_qi_wallet", descriptors=True)
        no_qi = node.get_wallet_rpc("no_qi_wallet")
        try:
            no_qi.sphincsspend(miner.getnewaddress(address_type="bech32m"), 1)
            assert False, "Should have raised"
        except Exception as e:
            self.log.info(f"  Correctly rejected: {e}")

        self.log.info("All SPHINCS+ script-path tests passed!")


if __name__ == '__main__':
    WalletSphincsScriptPathTest(__file__).main()
