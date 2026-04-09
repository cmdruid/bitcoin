#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP 368 (Key-Path Hardening for Taproot).

Tests that key-path spends require the internal public key in the annex
(type byte 0x02), bans the NUMS point, and disables bare-key spending.
"""

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.key import (
    compute_xonly_pubkey,
    sign_schnorr,
    TaggedHash,
    tweak_add_pubkey,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    msg_block,
    SEQUENCE_FINAL,
)
from test_framework.p2p import P2PInterface
from test_framework.script import (
    CScript,
    OP_1,
    TaprootSignatureHash,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet, MiniWalletMode

# secp256k1 order
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# BIP 341 NUMS point
NUMS_H = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def build_keypath_annex(internal_pubkey, merkle_root=None):
    """Build a BIP 368 key-path annex (type 0x02).

    34 bytes without script tree, 66 bytes with merkle root.
    """
    annex = bytes([0x50, 0x02]) + internal_pubkey
    if merkle_root is not None and len(merkle_root) == 32:
        annex += merkle_root
    return annex


def compute_tweaked_privkey(privkey_bytes, pubkey_bytes, merkle_root=None):
    """Compute the tweaked private key for key-path signing.

    privkey_bytes: 32-byte private key
    pubkey_bytes: 32-byte x-only public key
    merkle_root: 32-byte merkle root (or None for no script tree)
    """
    privkey_int = int.from_bytes(privkey_bytes, 'big')

    # Check if the public key has odd y — if so, negate the privkey
    _, negated = compute_xonly_pubkey(privkey_bytes)
    if negated:
        privkey_int = ORDER - privkey_int

    # Compute tweak
    if merkle_root is not None and len(merkle_root) == 32:
        tweak = TaggedHash("TapTweak", pubkey_bytes + merkle_root)
    else:
        tweak = TaggedHash("TapTweak", pubkey_bytes)

    tweak_int = int.from_bytes(tweak, 'big')
    tweaked_privkey = (privkey_int + tweak_int) % ORDER
    return tweaked_privkey.to_bytes(32, 'big')


class KeypathHardeningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.noban_tx_relay = True
        self.extra_args = [['-acceptnonstdtxn=1']]
        self.setup_clean_chain = True

    def create_taproot_utxo(self, wallet, tap_info):
        utxo = wallet.send_to(
            from_node=self.nodes[0],
            scriptPubKey=tap_info.scriptPubKey,
            amount=50000,
        )
        return {"txid": utxo["txid"], "vout": utxo["sent_vout"], "value": 50000,
                "scriptPubKey": tap_info.scriptPubKey}

    def assert_accepted(self, tx, msg=""):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        assert_equal(result[0]["allowed"], True)
        self.log.info(f"  -> PASSED{' (' + msg + ')' if msg else ''}")

    def assert_rejected(self, tx, reason_substring=None, msg=""):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        assert_equal(result[0]["allowed"], False)
        if reason_substring:
            assert reason_substring in result[0]["reject-reason"], \
                f"Expected '{reason_substring}' in reject reason, got: {result[0]['reject-reason']}"
        self.log.info(f"  -> REJECTED{' (' + msg + ')' if msg else ''}: {result[0]['reject-reason']}")

    def build_keypath_spend(self, utxo, tap_info, privkey, annex_override=None, merkle_root_override=None):
        """Build a key-path spending tx with BIP 368 annex."""
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_info.output_pubkey]))]

        spent_utxo = CTxOut(utxo["value"], utxo["scriptPubKey"])

        if annex_override is not None:
            annex = annex_override
        else:
            mr = merkle_root_override if merkle_root_override is not None else \
                 (tap_info.merkle_root if len(tap_info.merkle_root) == 32 else None)
            annex = build_keypath_annex(tap_info.internal_pubkey, mr)

        # Compute tweaked private key
        mr_for_tweak = tap_info.merkle_root if len(tap_info.merkle_root) == 32 else None
        tweaked_priv = compute_tweaked_privkey(privkey, tap_info.internal_pubkey, mr_for_tweak)

        # Compute sighash (key-path, with annex)
        sighash = TaprootSignatureHash(
            tx, [spent_utxo], hash_type=0,
            input_index=0, scriptpath=False, annex=annex,
        )
        sig = sign_schnorr(tweaked_priv, sighash)

        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, annex]
        return tx

    def run_test(self):
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_TRUE)
        self.generate(wallet, 110)

        privkey = (1).to_bytes(32, 'big')
        pubkey, _ = compute_xonly_pubkey(privkey)
        privkey2 = (2).to_bytes(32, 'big')
        pubkey2, _ = compute_xonly_pubkey(privkey2)

        # ===================================================================
        # SECTION 1: SUCCESS CASES
        # ===================================================================
        self.log.info("=== Section 1: Success Cases ===")

        self.log.info("Test 1.1: Key-path with annex, no script tree (34 bytes)")
        tap_no_tree = taproot_construct(pubkey)
        utxo = self.create_taproot_utxo(wallet, tap_no_tree)
        self.generate(self.nodes[0], 1)
        tx = self.build_keypath_spend(utxo, tap_no_tree, privkey)
        self.assert_accepted(tx)

        self.log.info("Test 1.2: Key-path with annex, with script tree (66 bytes)")
        tap_with_tree = taproot_construct(pubkey, [("leaf", CScript([OP_1]))])
        utxo = self.create_taproot_utxo(wallet, tap_with_tree)
        self.generate(self.nodes[0], 1)
        tx = self.build_keypath_spend(utxo, tap_with_tree, privkey)
        self.assert_accepted(tx)

        self.log.info("Test 1.3: Script-path spend unaffected by BIP 368")
        utxo = self.create_taproot_utxo(wallet, tap_with_tree)
        self.generate(self.nodes[0], 1)
        # Script-path spend — no BIP 368 annex needed
        leaf = tap_with_tree.leaves["leaf"]
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_with_tree.output_pubkey]))]
        control_block = bytes([0xc0 + tap_with_tree.negflag]) + tap_with_tree.internal_pubkey + leaf.merklebranch
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(leaf.script), control_block]
        self.assert_accepted(tx, "script-path, no annex needed")

        # ===================================================================
        # SECTION 2: FAILURE CASES
        # ===================================================================
        self.log.info("=== Section 2: Failure Cases ===")

        self.log.info("Test 2.1: Key-path without annex fails")
        utxo = self.create_taproot_utxo(wallet, tap_no_tree)
        self.generate(self.nodes[0], 1)
        # Build tx with just a signature (no annex) — use tweaked privkey
        mr_for_tweak = None
        tweaked_priv = compute_tweaked_privkey(privkey, tap_no_tree.internal_pubkey, mr_for_tweak)
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_no_tree.output_pubkey]))]
        spent = CTxOut(utxo["value"], utxo["scriptPubKey"])
        sighash = TaprootSignatureHash(tx, [spent], hash_type=0, input_index=0, scriptpath=False)
        sig = sign_schnorr(tweaked_priv, sighash)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig]
        self.assert_rejected(tx, "Key-path spend requires annex", "no annex")

        self.log.info("Test 2.2: Key-path with wrong annex type byte fails")
        utxo = self.create_taproot_utxo(wallet, tap_no_tree)
        self.generate(self.nodes[0], 1)
        bad_annex = bytes([0x50, 0x04]) + pubkey  # type 0x04 (SPHINCS+ type)
        tx = self.build_keypath_spend(utxo, tap_no_tree, privkey, annex_override=bad_annex)
        self.assert_rejected(tx, "wrong type byte or length", "wrong type byte")

        self.log.info("Test 2.3: Key-path with wrong annex length fails")
        utxo = self.create_taproot_utxo(wallet, tap_no_tree)
        self.generate(self.nodes[0], 1)
        bad_annex = bytes([0x50, 0x02]) + pubkey + b'\x00'  # 35 bytes (not 34 or 66)
        tx = self.build_keypath_spend(utxo, tap_no_tree, privkey, annex_override=bad_annex)
        self.assert_rejected(tx, "wrong type byte or length", "wrong length")

        self.log.info("Test 2.4: Key-path with NUMS internal key fails")
        tap_nums = taproot_construct(NUMS_H)
        utxo = self.create_taproot_utxo(wallet, tap_nums)
        self.generate(self.nodes[0], 1)
        # We can't sign properly (don't know NUMS privkey), but NUMS ban fires before sig check
        annex = build_keypath_annex(NUMS_H)
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_nums.output_pubkey]))]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(64), annex]  # dummy 64-byte sig
        self.assert_rejected(tx, "NUMS internal key is banned", "NUMS banned")

        self.log.info("Test 2.5: Key-path with wrong internal key fails")
        utxo = self.create_taproot_utxo(wallet, tap_no_tree)
        self.generate(self.nodes[0], 1)
        # Provide pubkey2 as internal key (doesn't reconstruct tap_no_tree's output key)
        bad_annex = build_keypath_annex(pubkey2)
        tx = self.build_keypath_spend(utxo, tap_no_tree, privkey, annex_override=bad_annex)
        self.assert_rejected(tx, "does not reconstruct", "wrong internal key")

        self.log.info("Test 2.6: Key-path with wrong merkle root fails")
        utxo = self.create_taproot_utxo(wallet, tap_with_tree)
        self.generate(self.nodes[0], 1)
        wrong_root = bytes(32)  # all zeros, not the real merkle root
        bad_annex = build_keypath_annex(tap_with_tree.internal_pubkey, wrong_root)
        tx = self.build_keypath_spend(utxo, tap_with_tree, privkey, annex_override=bad_annex)
        self.assert_rejected(tx, "does not reconstruct", "wrong merkle root")

        self.log.info("All key-path hardening tests passed!")


class KeypathHardeningActivationTest(BitcoinTestFramework):
    """Test pre/post activation behavior of BIP 368."""

    KEYPATH_HEIGHT = 300

    def set_test_params(self):
        self.num_nodes = 1
        self.noban_tx_relay = True
        self.extra_args = [[
            f'-testactivationheight=keypath_hardening@{self.KEYPATH_HEIGHT}',
            '-acceptnonstdtxn=1',
        ]]
        self.setup_clean_chain = True

    def create_taproot_utxo(self, wallet, tap_info):
        utxo = wallet.send_to(
            from_node=self.nodes[0],
            scriptPubKey=tap_info.scriptPubKey,
            amount=50000,
        )
        return {"txid": utxo["txid"], "vout": utxo["sent_vout"], "value": 50000,
                "scriptPubKey": tap_info.scriptPubKey}

    def run_test(self):
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_TRUE)
        privkey = (1).to_bytes(32, 'big')
        pubkey, _ = compute_xonly_pubkey(privkey)

        tap = taproot_construct(pubkey)

        # Mine funds and pre-fund UTXOs
        self.generate(wallet, 110)
        utxo_pre = self.create_taproot_utxo(wallet, tap)
        utxo_post_noannex = self.create_taproot_utxo(wallet, tap)
        utxo_post_annex = self.create_taproot_utxo(wallet, tap)

        # Mine to pre-activation
        self.log.info(f"Mining to height {self.KEYPATH_HEIGHT - 5}")
        current = self.nodes[0].getblockcount()
        self.generate(self.nodes[0], self.KEYPATH_HEIGHT - 5 - current)

        # ===================================================================
        # PRE-ACTIVATION
        # ===================================================================
        self.log.info("=== Pre-Activation Tests ===")

        self.log.info("Test 3.1: Deployment info shows inactive")
        info = self.nodes[0].getdeploymentinfo()['deployments']['keypath_hardening']
        assert_equal(info['active'], False)
        self.log.info(f"  -> PASSED (active={info['active']}, height={info['height']})")

        self.log.info("Test 3.2: Key-path without annex accepted in pre-activation block")
        peer = self.nodes[0].add_p2p_connection(P2PInterface())
        # Build key-path spend WITHOUT annex (legacy style)
        mr_for_tweak = None
        tweaked_priv = compute_tweaked_privkey(privkey, tap.internal_pubkey, mr_for_tweak)
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo_pre["txid"], 16), utxo_pre["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo_pre["value"] - 1000, CScript([OP_1, tap.output_pubkey]))]
        spent = CTxOut(utxo_pre["value"], utxo_pre["scriptPubKey"])
        sighash = TaprootSignatureHash(tx, [spent], hash_type=0, input_index=0, scriptpath=False)
        sig = sign_schnorr(tweaked_priv, sighash)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig]

        tip = self.nodes[0].getbestblockhash()
        height = self.nodes[0].getblockcount() + 1
        block_time = self.nodes[0].getblockheader(tip)['mediantime'] + 1
        block = create_block(int(tip, 16), create_coinbase(height), block_time, txlist=[tx])
        add_witness_commitment(block)
        block.solve()
        peer.send_and_ping(msg_block(block))
        assert_equal(self.nodes[0].getbestblockhash(), block.hash_hex)
        self.log.info("  -> PASSED (block accepted, no annex needed pre-activation)")

        # ===================================================================
        # POST-ACTIVATION
        # ===================================================================
        self.log.info(f"Mining past activation height {self.KEYPATH_HEIGHT}")
        current = self.nodes[0].getblockcount()
        self.generate(self.nodes[0], self.KEYPATH_HEIGHT - current + 1)

        info = self.nodes[0].getdeploymentinfo()['deployments']['keypath_hardening']
        assert_equal(info['active'], True)

        self.log.info("Test 3.3: Key-path without annex rejected post-activation")
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo_post_noannex["txid"], 16), utxo_post_noannex["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo_post_noannex["value"] - 1000, CScript([OP_1, tap.output_pubkey]))]
        spent = CTxOut(utxo_post_noannex["value"], utxo_post_noannex["scriptPubKey"])
        sighash = TaprootSignatureHash(tx, [spent], hash_type=0, input_index=0, scriptpath=False)
        sig = sign_schnorr(tweaked_priv, sighash)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig]
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        assert_equal(result[0]["allowed"], False)
        assert "Key-path spend requires annex" in result[0]["reject-reason"]
        self.log.info(f"  -> REJECTED: {result[0]['reject-reason']}")

        self.log.info("Test 3.4: Key-path with annex accepted post-activation")
        annex = build_keypath_annex(tap.internal_pubkey)
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo_post_annex["txid"], 16), utxo_post_annex["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo_post_annex["value"] - 1000, CScript([OP_1, tap.output_pubkey]))]
        spent = CTxOut(utxo_post_annex["value"], utxo_post_annex["scriptPubKey"])
        sighash = TaprootSignatureHash(tx, [spent], hash_type=0, input_index=0, scriptpath=False, annex=annex)
        sig = sign_schnorr(tweaked_priv, sighash)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, annex]
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        assert_equal(result[0]["allowed"], True)
        self.log.info("  -> PASSED (key-path with annex accepted post-activation)")

        self.log.info("All activation tests passed!")


if __name__ == '__main__':
    import sys
    if '--activation' in sys.argv:
        sys.argv.remove('--activation')
        KeypathHardeningActivationTest(__file__).main()
    else:
        KeypathHardeningTest(__file__).main()
