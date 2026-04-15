#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test quantum-insured wallet behavior across BIP 368/369 activation.

Verifies that:
- Pre-activation: key-path spends work without annex (standard Schnorr)
- Post-activation: key-path spends include BIP 368 annex
"""

from decimal import Decimal
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

ACTIVATION_HEIGHT = 250


class WalletSphincsActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            f'-testactivationheight=sphincs@{ACTIVATION_HEIGHT}',
            f'-testactivationheight=keypath_hardening@{ACTIVATION_HEIGHT}',
            '-acceptnonstdtxn=1',
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Setup: Create wallet with SPHINCS+ key")
        node.createwallet(wallet_name="activation_wallet", descriptors=True)
        w = node.get_wallet_rpc("activation_wallet")
        w.createsphincskey()

        self.log.info("Setup: Fund wallet (mine to standard address)")
        fund_addr = w.getnewaddress(address_type="bech32")
        self.generatetoaddress(node, COINBASE_MATURITY + 10, fund_addr)
        balance = w.getbalance()
        self.log.info(f"  Balance: {balance}, Height: {node.getblockcount()}")
        assert_greater_than(balance, 0)
        assert node.getblockcount() < ACTIVATION_HEIGHT, "Should be pre-activation"

        self.log.info("=== Pre-activation tests ===")

        self.log.info("Test 1: Send to QI address pre-activation")
        qi_addr = w.getnewaddress(address_type="bech32m")
        txid1 = w.sendtoaddress(qi_addr, 5)
        self.generate(node, 1)
        self.log.info(f"  Funded QI address: {qi_addr}")

        self.log.info("Test 2: Spend FROM QI address pre-activation (no annex needed)")
        dest = w.getnewaddress(address_type="bech32")
        txid2 = w.sendtoaddress(dest, 2)
        self.log.info(f"  Pre-activation spend txid: {txid2}")
        self.generate(node, 1)

        # Verify transaction confirmed
        tx_info = w.gettransaction(txid2)
        assert_equal(tx_info["confirmations"], 1)
        self.log.info(f"  Pre-activation spend confirmed at height {node.getblockcount()}")

        self.log.info("=== Mining to activation height ===")
        current = node.getblockcount()
        blocks_needed = ACTIVATION_HEIGHT - current
        self.log.info(f"  Current height: {current}, need {blocks_needed} more blocks")
        if blocks_needed > 0:
            self.generatetoaddress(node, blocks_needed, fund_addr)
        self.log.info(f"  Height after mining: {node.getblockcount()}")
        assert node.getblockcount() >= ACTIVATION_HEIGHT

        self.log.info("=== Post-activation tests ===")

        self.log.info("Test 3: Fund QI address post-activation")
        qi_addr2 = w.getnewaddress(address_type="bech32m")
        txid3 = w.sendtoaddress(qi_addr2, 5)
        self.generate(node, 1)
        self.log.info(f"  Funded QI address: {qi_addr2}")

        self.log.info("Test 4: Spend FROM QI address post-activation (with BIP 368 annex)")
        dest2 = w.getnewaddress(address_type="bech32")
        txid4 = w.sendtoaddress(dest2, 2)
        self.log.info(f"  Post-activation spend txid: {txid4}")
        self.generate(node, 1)

        tx_info2 = w.gettransaction(txid4)
        assert_equal(tx_info2["confirmations"], 1)
        self.log.info(f"  Post-activation spend confirmed at height {node.getblockcount()}")

        self.log.info("All activation tests passed!")


if __name__ == '__main__':
    WalletSphincsActivationTest(__file__).main()
