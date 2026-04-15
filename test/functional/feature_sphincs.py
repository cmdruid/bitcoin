#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP 369 (OP_CHECKSPHINCSVERIFY).

Comprehensive test coverage for OP_CHECKSPHINCSVERIFY including:
- Success cases (hybrid, SPHINCS+-only, multi-sig)
- Non-upgraded node behavior (NOP4 passthrough)
- Hybrid security model (Schnorr/SPHINCS+ independence)
- Invalid signature rejection
- Annex format edge cases
- Conditional branch cursor behavior
- Unknown key types
- Stack edge cases
- Block-level validation
"""

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.key import (
    compute_xonly_pubkey,
    sign_schnorr,
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
    OP_0,
    OP_1,
    OP_CHECKSIGVERIFY,
    OP_CHECKSPHINCSVERIFY,
    OP_CODESEPARATOR,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_IF,
    SphincsSignatureHash,
    SphincsSignatureMsg,
    TaggedHash,
    TaprootSignatureHash,
    taproot_construct,
)
from test_framework.sphincs import (
    SPHINCS_SIG_SIZE,
    SphincsKey,
    build_sphincs_annex,
)
from feature_keypath_hardening import (
    build_keypath_annex,
    compute_tweaked_privkey,
    NUMS_H,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet, MiniWalletMode


class SphincsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.noban_tx_relay = True
        self.extra_args = [[
            '-acceptnonstdtxn=1',
        ]]
        self.setup_clean_chain = True

    def create_taproot_utxo(self, wallet, tap_info):
        """Create a Taproot output using MiniWallet and return the UTXO info."""
        utxo = wallet.send_to(
            from_node=self.nodes[0],
            scriptPubKey=tap_info.scriptPubKey,
            amount=50000,
        )
        return {"txid": utxo["txid"], "vout": utxo["sent_vout"], "value": 50000, "scriptPubKey": tap_info.scriptPubKey}

    def spend_sphincs_tapscript(self, utxo, tap_info, leaf_name, schnorr_privkey, sphincs_keys,
                                annex_override=None, corrupt_schnorr=False, corrupt_sphincs=False,
                                codeseparator_pos=0xFFFFFFFF, extra_witness_prefix=None):
        """Create a transaction spending a Taproot UTXO via script-path with SPHINCS+ annex."""
        leaf = tap_info.leaves[leaf_name]
        leaf_script = leaf.script

        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_info.output_pubkey]))]

        spent_utxo = CTxOut(utxo["value"], utxo["scriptPubKey"])

        # Step 1: Compute SPHINCS+ signatures (sighash without sha_annex)
        sphincs_sigs = []
        for skey in sphincs_keys:
            sphincs_hash = SphincsSignatureHash(
                tx, [spent_utxo], input_index=0,
                leaf_script=leaf_script,
                codeseparator_pos=codeseparator_pos,
                annex=b'\x50',
            )
            sphincs_sigs.append(skey.sign(sphincs_hash))

        # Step 2: Build annex
        if annex_override is not None:
            annex = annex_override
        else:
            annex = build_sphincs_annex(sphincs_sigs)

        # Optionally corrupt SPHINCS+ signatures after annex is built
        if corrupt_sphincs and annex_override is None:
            annex_list = bytearray(annex)
            # Flip a byte in the first signature
            annex_list[3] ^= 0xFF
            annex = bytes(annex_list)

        # Step 3: Compute Schnorr signature (sighash includes sha_annex)
        schnorr_sig = b''
        if schnorr_privkey is not None:
            schnorr_hash = TaprootSignatureHash(
                tx, [spent_utxo], hash_type=0,
                input_index=0, scriptpath=True,
                leaf_script=leaf_script,
                codeseparator_pos=codeseparator_pos,
                annex=annex,
            )
            schnorr_sig = sign_schnorr(schnorr_privkey, schnorr_hash)
            if corrupt_schnorr:
                schnorr_sig = bytearray(schnorr_sig)
                schnorr_sig[0] ^= 0xFF
                schnorr_sig = bytes(schnorr_sig)

        # Step 4: Build witness stack
        control_block = bytes([0xc0 + tap_info.negflag]) + tap_info.internal_pubkey + leaf.merklebranch

        witness_items = []
        if extra_witness_prefix is not None:
            witness_items.extend(extra_witness_prefix)
        if schnorr_privkey is not None:
            witness_items.append(schnorr_sig)

        witness_stack = witness_items + [bytes(leaf_script), control_block, annex]

        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = witness_stack
        return tx

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

    def run_test(self):
        peer = self.nodes[0].add_p2p_connection(P2PInterface())
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_TRUE)

        self.generate(wallet, 110)

        # Set up keys
        schnorr_privkey = (1).to_bytes(32, 'big')
        schnorr_pubkey, _ = compute_xonly_pubkey(schnorr_privkey)
        schnorr_privkey2 = (2).to_bytes(32, 'big')
        schnorr_pubkey2, _ = compute_xonly_pubkey(schnorr_privkey2)
        sphincs_key1 = SphincsKey(b'\x01' * 16)
        sphincs_key2 = SphincsKey(b'\x02' * 16)
        sphincs_key3 = SphincsKey(b'\x03' * 16)

        # Common scripts
        hybrid_script = CScript([
            schnorr_pubkey, OP_CHECKSIGVERIFY,
            sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            OP_1,
        ])
        sphincs_only_script = CScript([
            sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            OP_1,
        ])

        # ===================================================================
        # SECTION 1: SUCCESS CASES
        # ===================================================================
        self.log.info("=== Section 1: Success Cases ===")

        self.log.info("Test 1.1: Hybrid script (Schnorr + SPHINCS+) passes")
        tap = taproot_construct(schnorr_pubkey, [("hybrid", hybrid_script)])
        utxo = self.create_taproot_utxo(wallet, tap)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap, "hybrid", schnorr_privkey, [sphincs_key1])
        self.assert_accepted(tx)

        self.log.info("Test 1.2: SPHINCS+-only script passes")
        tap2 = taproot_construct(schnorr_pubkey, [("sphincs_only", sphincs_only_script)])
        utxo = self.create_taproot_utxo(wallet, tap2)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap2, "sphincs_only", None, [sphincs_key1])
        self.assert_accepted(tx)

        self.log.info("Test 1.3: Multiple SPHINCS+ signatures in one script")
        multi_script = CScript([
            sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            sphincs_key2.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            OP_1,
        ])
        tap_multi = taproot_construct(schnorr_pubkey, [("multi", multi_script)])
        utxo = self.create_taproot_utxo(wallet, tap_multi)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap_multi, "multi", None, [sphincs_key1, sphincs_key2])
        self.assert_accepted(tx)

        self.log.info("Test 1.4: 2-of-3 SPHINCS+ via MAST (3 tapleaves)")
        leaf_a_script = CScript([sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
                                  sphincs_key2.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP, OP_1])
        leaf_b_script = CScript([sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
                                  sphincs_key3.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP, OP_1])
        leaf_c_script = CScript([sphincs_key2.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
                                  sphincs_key3.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP, OP_1])
        tap_mast = taproot_construct(schnorr_pubkey, [("leaf_a", leaf_a_script),
                                                        ("leaf_b", leaf_b_script),
                                                        ("leaf_c", leaf_c_script)])
        # Spend via leaf_b (keys 1 and 3)
        utxo = self.create_taproot_utxo(wallet, tap_mast)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap_mast, "leaf_b", None, [sphincs_key1, sphincs_key3])
        self.assert_accepted(tx, "leaf_b: keys 1+3")

        # Spend via leaf_c (keys 2 and 3)
        utxo = self.create_taproot_utxo(wallet, tap_mast)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap_mast, "leaf_c", None, [sphincs_key2, sphincs_key3])
        self.assert_accepted(tx, "leaf_c: keys 2+3")

        # ===================================================================
        # SECTION 2: INVALID SIGNATURE REJECTION
        # ===================================================================
        self.log.info("=== Section 2: Invalid Signature Rejection ===")

        self.log.info("Test 2.1: Corrupted SPHINCS+ signature fails")
        utxo = self.create_taproot_utxo(wallet, tap2)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap2, "sphincs_only", None, [sphincs_key1], corrupt_sphincs=True)
        self.assert_rejected(tx, "script-verify-flag-failed")

        self.log.info("Test 2.2: Wrong SPHINCS+ pubkey (valid sig, different signer) fails")
        # Script expects sphincs_key1.pubkey but we sign with sphincs_key2
        wrong_key_script = CScript([
            sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP, OP_1,
        ])
        tap_wrong = taproot_construct(schnorr_pubkey, [("wrong", wrong_key_script)])
        utxo = self.create_taproot_utxo(wallet, tap_wrong)
        self.generate(self.nodes[0], 1)
        # Sign with key2 but script has key1's pubkey
        tx = self.spend_sphincs_tapscript(utxo, tap_wrong, "wrong", None, [sphincs_key2])
        self.assert_rejected(tx, "script-verify-flag-failed")

        # ===================================================================
        # SECTION 3: HYBRID SECURITY MODEL
        # ===================================================================
        self.log.info("=== Section 3: Hybrid Security Model ===")

        self.log.info("Test 3.1: Valid Schnorr + invalid SPHINCS+ fails on upgraded node")
        utxo = self.create_taproot_utxo(wallet, tap)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap, "hybrid", schnorr_privkey, [sphincs_key1], corrupt_sphincs=True)
        self.assert_rejected(tx, "script-verify-flag-failed", "SPHINCS+ corrupted")

        self.log.info("Test 3.2: Invalid Schnorr + valid SPHINCS+ fails on upgraded node")
        utxo = self.create_taproot_utxo(wallet, tap)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap, "hybrid", schnorr_privkey, [sphincs_key1], corrupt_schnorr=True)
        self.assert_rejected(tx, "script-verify-flag-failed", "Schnorr corrupted")

        # ===================================================================
        # SECTION 4: ANNEX FORMAT EDGE CASES
        # ===================================================================
        self.log.info("=== Section 4: Annex Format Edge Cases ===")

        self.log.info("Test 4.1: Missing annex fails")
        utxo = self.create_taproot_utxo(wallet, tap2)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap2, "sphincs_only", None, [sphincs_key1])
        tx.wit.vtxinwit[0].scriptWitness.stack.pop()  # Remove annex
        self.assert_rejected(tx, "script-verify-flag-failed")

        self.log.info("Test 4.2: Bad annex type byte fails")
        utxo = self.create_taproot_utxo(wallet, tap2)
        self.generate(self.nodes[0], 1)
        bad_annex = bytes([0x50, 0x02]) + bytes([1]) + bytes(SPHINCS_SIG_SIZE)
        tx = self.spend_sphincs_tapscript(utxo, tap2, "sphincs_only", None, [sphincs_key1], annex_override=bad_annex)
        self.assert_rejected(tx, "script-verify-flag-failed")

        self.log.info("Test 4.3: Annex with trailing data fails")
        utxo = self.create_taproot_utxo(wallet, tap2)
        self.generate(self.nodes[0], 1)
        # Build a valid annex then append an extra byte
        valid_sig = sphincs_key1.sign(b'\x00' * 32)  # sighash doesn't matter; format check fails first
        trailing_annex = build_sphincs_annex([valid_sig]) + b'\x00'  # Extra trailing byte
        tx = self.spend_sphincs_tapscript(utxo, tap2, "sphincs_only", None, [sphincs_key1], annex_override=trailing_annex)
        self.assert_rejected(tx, "script-verify-flag-failed")

        self.log.info("Test 4.4: Annex claims N=2 but only has 1 signature fails")
        utxo = self.create_taproot_utxo(wallet, tap2)
        self.generate(self.nodes[0], 1)
        # Manually craft annex: type=0x01, N=2, but only one sig worth of data
        short_annex = bytes([0x50, 0x04, 2]) + bytes(SPHINCS_SIG_SIZE)
        tx = self.spend_sphincs_tapscript(utxo, tap2, "sphincs_only", None, [sphincs_key1], annex_override=short_annex)
        self.assert_rejected(tx, "script-verify-flag-failed")

        self.log.info("Test 4.5: Unconsumed signatures fail")
        utxo = self.create_taproot_utxo(wallet, tap2)
        self.generate(self.nodes[0], 1)
        # Build annex with 2 sigs but script only consumes 1
        sig1 = sphincs_key1.sign(b'\x00' * 32)
        extra_sig = sphincs_key2.sign(b'\x00' * 32)
        two_sig_annex = build_sphincs_annex([sig1, extra_sig])
        tx = self.spend_sphincs_tapscript(utxo, tap2, "sphincs_only", None, [sphincs_key1], annex_override=two_sig_annex)
        self.assert_rejected(tx, "script-verify-flag-failed")

        # ===================================================================
        # SECTION 5: UNKNOWN KEY TYPES
        # ===================================================================
        self.log.info("=== Section 5: Unknown Key Types ===")

        self.log.info("Test 5.1: 31-byte pubkey (unknown type) passes with cursor advance")
        short_pk = b'\xaa' * 31
        unknown_key_script = CScript([
            short_pk, OP_CHECKSPHINCSVERIFY, OP_DROP, OP_1,
        ])
        tap_unk = taproot_construct(schnorr_pubkey, [("unknown", unknown_key_script)])
        utxo = self.create_taproot_utxo(wallet, tap_unk)
        self.generate(self.nodes[0], 1)
        # Need a dummy signature in the annex (consumed but not verified)
        dummy_sig = bytes(SPHINCS_SIG_SIZE)
        dummy_annex = build_sphincs_annex([dummy_sig])
        tx = self.spend_sphincs_tapscript(utxo, tap_unk, "unknown", None, [sphincs_key1], annex_override=dummy_annex)
        self.assert_accepted(tx, "31-byte pk, cursor advances")

        self.log.info("Test 5.2: 33-byte pubkey (unknown type) passes with cursor advance")
        long_pk = b'\xbb' * 33
        unknown_key_script2 = CScript([
            long_pk, OP_CHECKSPHINCSVERIFY, OP_DROP, OP_1,
        ])
        tap_unk2 = taproot_construct(schnorr_pubkey, [("unknown2", unknown_key_script2)])
        utxo = self.create_taproot_utxo(wallet, tap_unk2)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap_unk2, "unknown2", None, [sphincs_key1], annex_override=dummy_annex)
        self.assert_accepted(tx, "33-byte pk, cursor advances")

        # ===================================================================
        # SECTION 6: CONDITIONAL BRANCHES
        # ===================================================================
        self.log.info("=== Section 6: Conditional Branches ===")

        self.log.info("Test 6.1: OP_IF false — unexecuted CHECKSPHINCSVERIFY doesn't advance cursor")
        # Script: OP_IF <pk> OP_CHECKSPHINCSVERIFY OP_DROP OP_ENDIF 1
        # With condition=false, the CHECKSPHINCSVERIFY is not executed, cursor stays at 0
        cond_script = CScript([
            OP_IF,
            sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            OP_ENDIF,
            OP_1,
        ])
        tap_cond = taproot_construct(schnorr_pubkey, [("cond", cond_script)])
        utxo = self.create_taproot_utxo(wallet, tap_cond)
        self.generate(self.nodes[0], 1)
        # Annex with N=0 (no sigs), push OP_0 (false) for the OP_IF
        empty_annex = build_sphincs_annex([])
        leaf = tap_cond.leaves["cond"]
        leaf_script_bytes = bytes(leaf.script)
        control_block = bytes([0xc0 + tap_cond.negflag]) + tap_cond.internal_pubkey + leaf.merklebranch

        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_cond.output_pubkey]))]
        # Witness: [false_value, script, control_block, annex]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [b'', leaf_script_bytes, control_block, empty_annex]
        self.assert_accepted(tx, "unexecuted branch, 0 sigs consumed")

        self.log.info("Test 6.2: OP_IF true — executed CHECKSPHINCSVERIFY consumes sig")
        utxo = self.create_taproot_utxo(wallet, tap_cond)
        self.generate(self.nodes[0], 1)
        # Now push OP_1 (true) — the CHECKSPHINCSVERIFY executes, needs 1 sig
        spent_utxo = CTxOut(utxo["value"], utxo["scriptPubKey"])
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_cond.output_pubkey]))]

        sphincs_hash = SphincsSignatureHash(
            tx, [spent_utxo], input_index=0,
            leaf_script=leaf.script,
            codeseparator_pos=0xFFFFFFFF,
            annex=b'\x50',
        )
        sig = sphincs_key1.sign(sphincs_hash)
        one_sig_annex = build_sphincs_annex([sig])

        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x01', leaf_script_bytes, control_block, one_sig_annex]
        self.assert_accepted(tx, "executed branch, 1 sig consumed")

        # ===================================================================
        # SECTION 7: BLOCK-LEVEL VALIDATION (via sendrawtransaction)
        # ===================================================================
        self.log.info("=== Section 7: Block-Level Validation ===")

        self.log.info("Test 7.1: Valid SPHINCS+ transaction accepted by sendrawtransaction")
        utxo = self.create_taproot_utxo(wallet, tap2)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap2, "sphincs_only", None, [sphincs_key1])
        self.nodes[0].sendrawtransaction(tx.serialize().hex())
        self.generate(self.nodes[0], 1)  # Mine it into a block
        self.log.info("  -> PASSED (transaction mined)")

        self.log.info("Test 7.2: Invalid SPHINCS+ transaction rejected by sendrawtransaction")
        utxo = self.create_taproot_utxo(wallet, tap2)
        self.generate(self.nodes[0], 1)
        tx_bad = self.spend_sphincs_tapscript(utxo, tap2, "sphincs_only", None, [sphincs_key1], corrupt_sphincs=True)
        try:
            self.nodes[0].sendrawtransaction(tx_bad.serialize().hex())
            assert False, "Should have been rejected"
        except Exception as e:
            assert "script-verify-flag-failed" in str(e)
            self.log.info(f"  -> PASSED (rejected: {e})")

        # ===================================================================
        # SECTION 8: STACK EDGE CASES
        # ===================================================================
        self.log.info("=== Section 8: Stack Edge Cases ===")

        self.log.info("Test 8.1: Empty stack when CHECKSPHINCSVERIFY executes fails")
        # Script that reaches CHECKSPHINCSVERIFY with empty stack:
        # OP_1 OP_DROP removes the only item, then CHECKSPHINCSVERIFY hits empty stack
        empty_stack_script = CScript([
            OP_1, OP_DROP,
            OP_CHECKSPHINCSVERIFY, OP_DROP,
            OP_1,
        ])
        tap_es = taproot_construct(schnorr_pubkey, [("empty_stack", empty_stack_script)])
        utxo = self.create_taproot_utxo(wallet, tap_es)
        self.generate(self.nodes[0], 1)
        dummy_sig = bytes(SPHINCS_SIG_SIZE)
        dummy_annex = build_sphincs_annex([dummy_sig])
        leaf = tap_es.leaves["empty_stack"]
        control_block = bytes([0xc0 + tap_es.negflag]) + tap_es.internal_pubkey + leaf.merklebranch
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_es.output_pubkey]))]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(leaf.script), control_block, dummy_annex]
        self.assert_rejected(tx, "script-verify-flag-failed", "empty stack")

        self.log.info("Test 8.2: Cursor exceeds sig count (too few sigs in annex) fails")
        # Script with 2 CHECKSPHINCSVERIFY but annex with only 1 sig
        two_check_script = CScript([
            sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            sphincs_key2.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            OP_1,
        ])
        tap_2c = taproot_construct(schnorr_pubkey, [("two_check", two_check_script)])
        utxo = self.create_taproot_utxo(wallet, tap_2c)
        self.generate(self.nodes[0], 1)
        # Only provide 1 sig for 2 checks
        tx = self.spend_sphincs_tapscript(utxo, tap_2c, "two_check", None, [sphincs_key1])
        self.assert_rejected(tx, "script-verify-flag-failed", "too few sigs")

        # ===================================================================
        # SECTION 9: OP_CODESEPARATOR INTERACTION
        # ===================================================================
        self.log.info("=== Section 9: OP_CODESEPARATOR Interaction ===")

        self.log.info("Test 9.1: OP_CODESEPARATOR changes SPHINCS+ sighash")
        # Script with CODESEPARATOR before CHECKSPHINCSVERIFY
        codesep_script = CScript([
            OP_CODESEPARATOR,
            sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            OP_1,
        ])
        tap_cs = taproot_construct(schnorr_pubkey, [("codesep", codesep_script)])
        utxo = self.create_taproot_utxo(wallet, tap_cs)
        self.generate(self.nodes[0], 1)

        # Sign with codeseparator_pos=0 (the CODESEPARATOR is at position 0 in the script)
        tx = self.spend_sphincs_tapscript(utxo, tap_cs, "codesep", None, [sphincs_key1], codeseparator_pos=0)
        self.assert_accepted(tx, "codesep_pos=0")

        self.log.info("Test 9.2: Wrong codeseparator_pos fails verification")
        utxo = self.create_taproot_utxo(wallet, tap_cs)
        self.generate(self.nodes[0], 1)
        # Sign with wrong codeseparator_pos (0xFFFFFFFF = no codeseparator seen)
        tx = self.spend_sphincs_tapscript(utxo, tap_cs, "codesep", None, [sphincs_key1], codeseparator_pos=0xFFFFFFFF)
        self.assert_rejected(tx, "script-verify-flag-failed", "wrong codesep_pos")

        # ===================================================================
        # SECTION 10: SIGOPS BUDGET
        # ===================================================================
        self.log.info("=== Section 10: Sigops Budget ===")

        self.log.info("Test 10.1: Many SPHINCS+ sigs within budget passes")
        # Create a script with 3 SPHINCS+ checks — budget needs to accommodate all
        # Budget = witness_size + 50. Each SPHINCS+ sig = 4080 bytes in annex.
        # 3 sigs = 12240 bytes annex + overhead. Budget ~12300. Cost = 3 * 50 = 150. Should pass.
        three_check_script = CScript([
            sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            sphincs_key2.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            sphincs_key3.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            OP_1,
        ])
        tap_3c = taproot_construct(schnorr_pubkey, [("three_check", three_check_script)])
        utxo = self.create_taproot_utxo(wallet, tap_3c)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap_3c, "three_check", None,
                                           [sphincs_key1, sphincs_key2, sphincs_key3])
        self.assert_accepted(tx, "3 SPHINCS+ sigs within budget")

        # ===================================================================
        # SECTION 12: SIGHASH CROSS-VALIDATION
        # ===================================================================
        self.log.info("=== Section 12: Sighash Cross-Validation ===")

        self.log.info("Test 12.1: Python SphincsSignatureHash matches C++ (valid sig verifies)")
        # This is implicitly tested by all passing tests — Python computes
        # the sighash, C++ verifies the signature over it. But let's verify
        # the sighash structure explicitly.
        utxo = self.create_taproot_utxo(wallet, tap2)
        self.generate(self.nodes[0], 1)
        leaf = tap2.leaves["sphincs_only"]
        spent_utxo = CTxOut(utxo["value"], utxo["scriptPubKey"])

        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap2.output_pubkey]))]

        # Compute sighash via SphincsSignatureMsg (raw preimage) and verify structure
        sphincs_msg = SphincsSignatureMsg(
            tx, [spent_utxo], input_index=0,
            leaf_script=leaf.script, codeseparator_pos=0xFFFFFFFF, annex=b'\x50',
        )
        # Verify spend_type byte is 0x03 (ext_flag=1, annex_bit=1)
        # Structure: epoch(1) + hash_type(1) + version(4) + locktime(4) +
        #            sha_prevouts(32) + sha_amounts(32) + sha_scriptpubkeys(32) +
        #            sha_sequences(32) + sha_outputs(32) + spend_type(1) + in_pos(4)
        #            + tapleaf_hash(32) + key_version(1) + codesep_pos(4)
        spend_type_offset = 1 + 1 + 4 + 4 + 32 + 32 + 32 + 32 + 32  # = 170
        assert_equal(sphincs_msg[spend_type_offset], 0x03)
        # Verify NO sha_annex follows spend_type + in_pos (next field is tapleaf_hash)
        # Total without sha_annex: 170 + 1 + 4 + 32 + 1 + 4 = 212
        assert_equal(len(sphincs_msg), 212)

        sphincs_hash = TaggedHash("TapSighash", sphincs_msg)
        sig = sphincs_key1.sign(sphincs_hash)
        annex = build_sphincs_annex([sig])
        control_block = bytes([0xc0 + tap2.negflag]) + tap2.internal_pubkey + leaf.merklebranch
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(leaf.script), control_block, annex]
        self.assert_accepted(tx, "sighash structure verified, spend_type=0x03, len=212")

        # ===================================================================
        # SECTION 13: ANNEX MALLEABILITY PROTECTION
        # ===================================================================
        self.log.info("=== Section 13: Annex Malleability Protection ===")

        self.log.info("Test 13.1: Modifying annex after Schnorr signing invalidates Schnorr sig")
        utxo = self.create_taproot_utxo(wallet, tap)
        self.generate(self.nodes[0], 1)

        # Build a valid hybrid transaction
        tx = self.spend_sphincs_tapscript(utxo, tap, "hybrid", schnorr_privkey, [sphincs_key1])
        # Verify it's valid first
        self.assert_accepted(tx, "valid before modification")

        # Now send the SAME tx again after mining the previous one
        self.nodes[0].sendrawtransaction(tx.serialize().hex())
        self.generate(self.nodes[0], 1)

        # Build another valid hybrid tx, then modify annex after signing
        utxo = self.create_taproot_utxo(wallet, tap)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap, "hybrid", schnorr_privkey, [sphincs_key1])

        # Flip a byte in the annex (which is the last witness element)
        modified_annex = bytearray(tx.wit.vtxinwit[0].scriptWitness.stack[-1])
        modified_annex[10] ^= 0xFF
        tx.wit.vtxinwit[0].scriptWitness.stack[-1] = bytes(modified_annex)

        self.assert_rejected(tx, "script-verify-flag-failed", "annex modified after Schnorr signing")

        # ===================================================================
        # SECTION 14: SIGNING ORDER ENFORCEMENT
        # ===================================================================
        self.log.info("=== Section 14: Signing Order Enforcement ===")

        self.log.info("Test 14.1: Wrong signing order (Schnorr first) produces invalid tx")
        utxo = self.create_taproot_utxo(wallet, tap)
        self.generate(self.nodes[0], 1)
        leaf = tap.leaves["hybrid"]
        spent_utxo = CTxOut(utxo["value"], utxo["scriptPubKey"])

        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap.output_pubkey]))]

        # WRONG ORDER: Sign Schnorr first with a placeholder annex
        placeholder_annex = build_sphincs_annex([bytes(SPHINCS_SIG_SIZE)])
        schnorr_hash = TaprootSignatureHash(
            tx, [spent_utxo], hash_type=0,
            input_index=0, scriptpath=True,
            leaf_script=leaf.script, codeseparator_pos=0xFFFFFFFF,
            annex=placeholder_annex,
        )
        schnorr_sig = sign_schnorr(schnorr_privkey, schnorr_hash)

        # Then sign SPHINCS+ (correct sighash, but the annex will change)
        sphincs_hash = SphincsSignatureHash(
            tx, [spent_utxo], input_index=0,
            leaf_script=leaf.script, codeseparator_pos=0xFFFFFFFF, annex=b'\x50',
        )
        sphincs_sig = sphincs_key1.sign(sphincs_hash)
        real_annex = build_sphincs_annex([sphincs_sig])
        # real_annex != placeholder_annex, so the Schnorr sig is invalid
        # (Schnorr was signed over sha_annex of placeholder, not real annex)

        control_block = bytes([0xc0 + tap.negflag]) + tap.internal_pubkey + leaf.merklebranch
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [schnorr_sig, bytes(leaf.script), control_block, real_annex]

        self.assert_rejected(tx, "script-verify-flag-failed", "wrong signing order")

        # ===================================================================
        # SECTION 15: MULTIPLE OP_CODESEPARATOR POSITIONS
        # ===================================================================
        self.log.info("=== Section 15: Multiple OP_CODESEPARATOR ===")

        self.log.info("Test 15.1: Two CODESEPARATOR positions with two SPHINCS+ checks")
        # Script: CODESEP pk1 CHECKSPHINCSVERIFY DROP CODESEP pk2 CHECKSPHINCSVERIFY DROP 1
        # First sig uses codesep_pos from first CODESEPARATOR (position 0)
        # Second sig uses codesep_pos from second CODESEPARATOR
        multi_codesep_script = CScript([
            OP_CODESEPARATOR,                                       # position 0
            sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            OP_CODESEPARATOR,                                       # position 36
            sphincs_key2.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            OP_1,
        ])
        tap_mcs = taproot_construct(schnorr_pubkey, [("multi_codesep", multi_codesep_script)])
        utxo = self.create_taproot_utxo(wallet, tap_mcs)
        self.generate(self.nodes[0], 1)

        leaf = tap_mcs.leaves["multi_codesep"]
        spent_utxo = CTxOut(utxo["value"], utxo["scriptPubKey"])

        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_mcs.output_pubkey]))]

        # codesep_pos is the OPCODE INDEX (not byte offset)
        # Opcode 0: OP_CODESEPARATOR
        # Opcode 1: push pk1 (32 bytes)
        # Opcode 2: OP_CHECKSPHINCSVERIFY
        # Opcode 3: OP_DROP
        # Opcode 4: OP_CODESEPARATOR  <-- second codesep
        second_codesep_pos = 4

        # First SPHINCS+ sig: codesep_pos = 0 (first OP_CODESEPARATOR)
        sphincs_hash1 = SphincsSignatureHash(
            tx, [spent_utxo], input_index=0,
            leaf_script=leaf.script, codeseparator_pos=0, annex=b'\x50',
        )
        sig1 = sphincs_key1.sign(sphincs_hash1)

        # Second SPHINCS+ sig: codesep_pos = 4 (second OP_CODESEPARATOR)
        sphincs_hash2 = SphincsSignatureHash(
            tx, [spent_utxo], input_index=0,
            leaf_script=leaf.script, codeseparator_pos=second_codesep_pos, annex=b'\x50',
        )
        sig2 = sphincs_key2.sign(sphincs_hash2)

        annex = build_sphincs_annex([sig1, sig2])
        control_block = bytes([0xc0 + tap_mcs.negflag]) + tap_mcs.internal_pubkey + leaf.merklebranch
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(leaf.script), control_block, annex]
        self.assert_accepted(tx, "two codesep positions, both sigs valid")

        # ===================================================================
        # SECTION 16: ZERO-SIGNATURE ANNEX
        # ===================================================================
        self.log.info("=== Section 16: Zero-Signature Annex ===")

        self.log.info("Test 16.1: Annex with N=0 and no CHECKSPHINCSVERIFY passes")
        # A script with no SPHINCS+ opcodes but an annex with N=0 sigs
        # The annex is valid (0 sigs, 0 consumed), script has no CHECKSPHINCSVERIFY
        no_sphincs_script = CScript([OP_1])
        tap_ns = taproot_construct(schnorr_pubkey, [("no_sphincs", no_sphincs_script)])
        utxo = self.create_taproot_utxo(wallet, tap_ns)
        self.generate(self.nodes[0], 1)

        leaf = tap_ns.leaves["no_sphincs"]
        zero_annex = build_sphincs_annex([])  # N=0
        control_block = bytes([0xc0 + tap_ns.negflag]) + tap_ns.internal_pubkey + leaf.merklebranch
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_ns.output_pubkey]))]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(leaf.script), control_block, zero_annex]
        self.assert_accepted(tx, "N=0 annex, no CHECKSPHINCSVERIFY, 0 consumed")

        # ===================================================================
        # SECTION 17: BIP 368 INTERACTION (key-path hardening + SPHINCS+)
        # ===================================================================
        self.log.info("=== Section 17: BIP 368 Interaction ===")

        self.log.info("Test 17.1: Script-path SPHINCS+ spend works when BIP 368 is active")
        # BIP 368 only affects key-path spends. Script-path with annex type 0x04 should be unaffected.
        utxo = self.create_taproot_utxo(wallet, tap2)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, tap2, "sphincs_only", None, [sphincs_key1])
        self.assert_accepted(tx, "script-path SPHINCS+ unaffected by BIP 368")

        self.log.info("Test 17.2: NUMS internal key + SPHINCS+ leaf — key-path banned, script-path works")
        # The "full insurance" pattern: NUMS internal key with a SPHINCS+ tapleaf.
        # Key-path is banned (NUMS). Script-path SPHINCS+ works.
        sphincs_leaf_script = CScript([
            sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP, OP_1,
        ])
        tap_nums_sphincs = taproot_construct(NUMS_H, [("sphincs_leaf", sphincs_leaf_script)])
        utxo = self.create_taproot_utxo(wallet, tap_nums_sphincs)
        self.generate(self.nodes[0], 1)
        # Script-path spend with SPHINCS+ should work
        tx = self.spend_sphincs_tapscript(utxo, tap_nums_sphincs, "sphincs_leaf", None, [sphincs_key1])
        self.assert_accepted(tx, "NUMS key-path banned, SPHINCS+ script-path works")

        self.log.info("Test 17.3: NUMS internal key — key-path spend rejected")
        utxo = self.create_taproot_utxo(wallet, tap_nums_sphincs)
        self.generate(self.nodes[0], 1)
        # Try key-path spend with NUMS — should be banned by BIP 368
        annex_368 = build_keypath_annex(NUMS_H, tap_nums_sphincs.merkle_root)
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_nums_sphincs.output_pubkey]))]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(64), annex_368]  # dummy sig, NUMS ban fires first
        self.assert_rejected(tx, "NUMS internal key is banned", "NUMS key-path banned by BIP 368")

        self.log.info("Test 17.4: Key-path with annex 0x02, then separate script-path SPHINCS+ — both work")
        # Taproot output with normal internal key + SPHINCS+ leaf
        # Key-path spend uses annex 0x02, script-path uses annex 0x04
        hybrid_tap = taproot_construct(schnorr_pubkey, [("sphincs", sphincs_leaf_script)])
        # Key-path spend
        utxo = self.create_taproot_utxo(wallet, hybrid_tap)
        self.generate(self.nodes[0], 1)
        annex_368 = build_keypath_annex(hybrid_tap.internal_pubkey, hybrid_tap.merkle_root)
        tweaked_priv = compute_tweaked_privkey(schnorr_privkey, hybrid_tap.internal_pubkey,
                                               hybrid_tap.merkle_root if len(hybrid_tap.merkle_root) == 32 else None)
        spent_utxo = CTxOut(utxo["value"], utxo["scriptPubKey"])
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, hybrid_tap.output_pubkey]))]
        sighash = TaprootSignatureHash(tx, [spent_utxo], hash_type=0, input_index=0,
                                        scriptpath=False, annex=annex_368)
        sig = sign_schnorr(tweaked_priv, sighash)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, annex_368]
        self.assert_accepted(tx, "key-path with annex 0x02")

        # Script-path SPHINCS+ spend of same output type
        utxo = self.create_taproot_utxo(wallet, hybrid_tap)
        self.generate(self.nodes[0], 1)
        tx = self.spend_sphincs_tapscript(utxo, hybrid_tap, "sphincs", None, [sphincs_key1])
        self.assert_accepted(tx, "script-path with annex 0x04")

        self.log.info("All SPHINCS+ tests passed (post-activation)!")


class SphincsActivationTest(BitcoinTestFramework):
    """Test pre-activation and post-activation behavior of OP_CHECKSPHINCSVERIFY."""

    SPHINCS_HEIGHT = 300

    def set_test_params(self):
        self.num_nodes = 1
        self.noban_tx_relay = True
        self.extra_args = [[
            f'-testactivationheight=sphincs@{self.SPHINCS_HEIGHT}',
            '-acceptnonstdtxn=1',
        ]]
        self.setup_clean_chain = True

    def create_taproot_utxo(self, wallet, tap_info):
        utxo = wallet.send_to(
            from_node=self.nodes[0],
            scriptPubKey=tap_info.scriptPubKey,
            amount=50000,
        )
        return {"txid": utxo["txid"], "vout": utxo["sent_vout"], "value": 50000, "scriptPubKey": tap_info.scriptPubKey}

    def run_test(self):
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_TRUE)

        # Set up keys
        schnorr_privkey = (1).to_bytes(32, 'big')
        schnorr_pubkey, _ = compute_xonly_pubkey(schnorr_privkey)
        sphincs_key1 = SphincsKey(b'\x01' * 16)

        # Common scripts
        hybrid_script = CScript([
            schnorr_pubkey, OP_CHECKSIGVERIFY,
            sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            OP_1,
        ])
        sphincs_only_script = CScript([
            sphincs_key1.pubkey, OP_CHECKSPHINCSVERIFY, OP_DROP,
            OP_1,
        ])

        tap_hybrid = taproot_construct(schnorr_pubkey, [("hybrid", hybrid_script)])
        tap_sphincs = taproot_construct(schnorr_pubkey, [("sphincs_only", sphincs_only_script)])

        # Mine to get funds, then create all UTXOs before approaching activation
        self.log.info("Mining initial blocks for funds")
        self.generate(wallet, 110)

        # Pre-fund all UTXOs we'll need for all activation tests
        utxo_sphincs_pre = self.create_taproot_utxo(wallet, tap_sphincs)
        utxo_hybrid_pre1 = self.create_taproot_utxo(wallet, tap_hybrid)
        utxo_hybrid_pre2 = self.create_taproot_utxo(wallet, tap_hybrid)
        utxo_hybrid_post = self.create_taproot_utxo(wallet, tap_hybrid)
        # Block-level test UTXOs
        utxo_blk_sphincs = self.create_taproot_utxo(wallet, tap_sphincs)
        utxo_blk_hybrid_ok = self.create_taproot_utxo(wallet, tap_hybrid)
        utxo_blk_hybrid_bad_schnorr = self.create_taproot_utxo(wallet, tap_hybrid)
        utxo_blk_hybrid_post = self.create_taproot_utxo(wallet, tap_hybrid)

        # Mine to just before activation (all UTXOs now confirmed)
        self.log.info(f"Mining to height {self.SPHINCS_HEIGHT - 5} (pre-activation)")
        current = self.nodes[0].getblockcount()
        if current < self.SPHINCS_HEIGHT - 5:
            self.generate(self.nodes[0], self.SPHINCS_HEIGHT - 5 - current)
        assert_equal(self.nodes[0].getblockcount(), self.SPHINCS_HEIGHT - 5)

        # Verify deployment info
        deploy_info = self.nodes[0].getdeploymentinfo()['deployments']['sphincs']
        assert_equal(deploy_info['active'], False)

        # ===================================================================
        # PRE-ACTIVATION TESTS (OP_NOP4 behavior)
        # ===================================================================
        self.log.info("=== Pre-Activation Tests ===")

        self.log.info("Test 11.1: Deployment info shows inactive pre-activation")
        deploy_info = self.nodes[0].getdeploymentinfo()['deployments']['sphincs']
        assert_equal(deploy_info['active'], False)
        assert_equal(deploy_info['height'], self.SPHINCS_HEIGHT)
        self.log.info(f"  -> PASSED (active={deploy_info['active']}, height={deploy_info['height']})")

        self.log.info("Test 11.2: Mempool rejects OP_NOP4 pre-activation (DISCOURAGE_UPGRADABLE_NOPS)")
        # Pre-activation, CHECKSPHINCSVERIFY flag is not set. The mempool applies
        # DISCOURAGE_UPGRADABLE_NOPS which rejects OP_NOP4. This is correct behavior —
        # the opcode is not yet defined, so policy rejects it.
        leaf = tap_sphincs.leaves["sphincs_only"]
        spent_utxo = CTxOut(utxo_sphincs_pre["value"], utxo_sphincs_pre["scriptPubKey"])
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo_sphincs_pre["txid"], 16), utxo_sphincs_pre["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo_sphincs_pre["value"] - 1000, CScript([OP_1, tap_sphincs.output_pubkey]))]
        h = SphincsSignatureHash(tx, [spent_utxo], input_index=0,
                                  leaf_script=leaf.script, codeseparator_pos=0xFFFFFFFF, annex=b'\x50')
        sig = sphincs_key1.sign(h)
        annex = build_sphincs_annex([sig])
        cb = bytes([0xc0 + tap_sphincs.negflag]) + tap_sphincs.internal_pubkey + leaf.merklebranch
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(leaf.script), cb, annex]
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        assert_equal(result[0]["allowed"], False)
        assert "NOPx reserved" in result[0]["reject-reason"]
        self.log.info(f"  -> PASSED (rejected: {result[0]['reject-reason']})")

        # ===================================================================
        # PRE-ACTIVATION BLOCK-LEVEL TESTS (P2P)
        # ===================================================================
        self.log.info("=== Pre-Activation Block-Level Tests ===")
        peer = self.nodes[0].add_p2p_connection(P2PInterface())

        def build_sphincs_only_spend(utxo, key):
            leaf = tap_sphincs.leaves["sphincs_only"]
            spent = CTxOut(utxo["value"], utxo["scriptPubKey"])
            stx = CTransaction()
            stx.version = 2
            stx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
            stx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_sphincs.output_pubkey]))]
            sh = SphincsSignatureHash(stx, [spent], input_index=0,
                                      leaf_script=leaf.script, codeseparator_pos=0xFFFFFFFF, annex=b'\x50')
            sig = key.sign(sh)
            annex = build_sphincs_annex([sig])
            cb = bytes([0xc0 + tap_sphincs.negflag]) + tap_sphincs.internal_pubkey + leaf.merklebranch
            stx.wit.vtxinwit = [CTxInWitness()]
            stx.wit.vtxinwit[0].scriptWitness.stack = [bytes(leaf.script), cb, annex]
            return stx

        def build_hybrid_spend(utxo, schnorr_priv, sphincs_key, corrupt_schnorr=False, corrupt_sphincs=False):
            leaf = tap_hybrid.leaves["hybrid"]
            spent = CTxOut(utxo["value"], utxo["scriptPubKey"])
            stx = CTransaction()
            stx.version = 2
            stx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
            stx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_hybrid.output_pubkey]))]
            sh = SphincsSignatureHash(stx, [spent], input_index=0,
                                      leaf_script=leaf.script, codeseparator_pos=0xFFFFFFFF, annex=b'\x50')
            sphincs_sig = sphincs_key.sign(sh) if not corrupt_sphincs else bytes(SPHINCS_SIG_SIZE)
            annex = build_sphincs_annex([sphincs_sig])
            cb = bytes([0xc0 + tap_hybrid.negflag]) + tap_hybrid.internal_pubkey + leaf.merklebranch
            schnorr_hash = TaprootSignatureHash(stx, [spent], hash_type=0, input_index=0, scriptpath=True,
                                                 leaf_script=leaf.script, codeseparator_pos=0xFFFFFFFF, annex=annex)
            s_sig = sign_schnorr(schnorr_priv, schnorr_hash)
            if corrupt_schnorr:
                s_sig = bytearray(s_sig)
                s_sig[0] ^= 0xFF
                s_sig = bytes(s_sig)
            stx.wit.vtxinwit = [CTxInWitness()]
            stx.wit.vtxinwit[0].scriptWitness.stack = [s_sig, bytes(leaf.script), cb, annex]
            return stx

        def submit_block_with_tx(spend_tx, expect_accepted=True):
            tip = self.nodes[0].getbestblockhash()
            height = self.nodes[0].getblockcount() + 1
            block_time = self.nodes[0].getblockheader(tip)['mediantime'] + 1
            block = create_block(int(tip, 16), create_coinbase(height), block_time, txlist=[spend_tx])
            add_witness_commitment(block)
            block.solve()
            peer.send_and_ping(msg_block(block))
            if expect_accepted:
                assert_equal(self.nodes[0].getbestblockhash(), block.hash_hex)
            else:
                assert_equal(self.nodes[0].getbestblockhash(), tip)
            return block

        self.log.info("Test 11.3: SPHINCS+-only tx accepted in pre-activation block")
        spend_tx = build_sphincs_only_spend(utxo_blk_sphincs, sphincs_key1)
        submit_block_with_tx(spend_tx, expect_accepted=True)
        self.log.info("  -> PASSED (block accepted, NOP4 skipped)")

        self.log.info("Test 11.4: Valid Schnorr + invalid SPHINCS+ accepted in pre-activation block")
        spend_tx = build_hybrid_spend(utxo_blk_hybrid_ok, schnorr_privkey, sphincs_key1, corrupt_sphincs=True)
        submit_block_with_tx(spend_tx, expect_accepted=True)
        self.log.info("  -> PASSED (block accepted, Schnorr valid, NOP4 ignores bad SPHINCS+)")

        self.log.info("Test 11.5: Invalid Schnorr + valid SPHINCS+ rejected in pre-activation block")
        spend_tx = build_hybrid_spend(utxo_blk_hybrid_bad_schnorr, schnorr_privkey, sphincs_key1, corrupt_schnorr=True)
        submit_block_with_tx(spend_tx, expect_accepted=False)
        self.log.info("  -> PASSED (block rejected, Schnorr enforced pre-activation)")

        # ===================================================================
        # ACTIVATE AND TEST POST-ACTIVATION
        # ===================================================================
        self.log.info(f"Mining past activation height {self.SPHINCS_HEIGHT}")
        current = self.nodes[0].getblockcount()
        self.generate(self.nodes[0], self.SPHINCS_HEIGHT - current + 1)
        assert self.nodes[0].getblockcount() >= self.SPHINCS_HEIGHT

        deploy_info = self.nodes[0].getdeploymentinfo()['deployments']['sphincs']
        assert_equal(deploy_info['active'], True)

        self.log.info("Test 11.6: Valid Schnorr + invalid SPHINCS+ FAILS post-activation (mempool)")
        utxo = utxo_hybrid_post
        leaf = tap_hybrid.leaves["hybrid"]
        spent_utxo = CTxOut(utxo["value"], utxo["scriptPubKey"])

        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), SEQUENCE_FINAL)]
        tx.vout = [CTxOut(utxo["value"] - 1000, CScript([OP_1, tap_hybrid.output_pubkey]))]

        garbage_sig = bytes(SPHINCS_SIG_SIZE)
        annex = build_sphincs_annex([garbage_sig])
        control_block = bytes([0xc0 + tap_hybrid.negflag]) + tap_hybrid.internal_pubkey + leaf.merklebranch

        schnorr_hash = TaprootSignatureHash(
            tx, [spent_utxo], hash_type=0,
            input_index=0, scriptpath=True,
            leaf_script=leaf.script, codeseparator_pos=0xFFFFFFFF, annex=annex,
        )
        schnorr_sig = sign_schnorr(schnorr_privkey, schnorr_hash)

        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [schnorr_sig, bytes(leaf.script), control_block, annex]

        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])
        assert_equal(result[0]["allowed"], False)
        assert "script-verify-flag-failed" in result[0]["reject-reason"]
        self.log.info("  -> REJECTED (SPHINCS+ enforced post-activation)")

        self.log.info("Test 11.7: Valid Schnorr + invalid SPHINCS+ rejected in post-activation block")
        spend_tx = build_hybrid_spend(utxo_blk_hybrid_post, schnorr_privkey, sphincs_key1, corrupt_sphincs=True)
        submit_block_with_tx(spend_tx, expect_accepted=False)
        self.log.info("  -> PASSED (block rejected, SPHINCS+ enforced post-activation)")

        self.log.info("All activation tests passed!")


if __name__ == '__main__':
    import sys
    if '--activation' in sys.argv:
        sys.argv.remove('--activation')
        SphincsActivationTest(__file__).main()
    else:
        SphincsTest(__file__).main()

