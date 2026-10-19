# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Taproot miniscript wallets where two keys share the same public key but carry
# different chain codes (ie. two unspendable BIP-341 H keys).
#
# Run with simulator: python simulator.py --eff --set nfc=1 --headless
#                     py.test test_miniscript_same_pubkey.py --sim --headless
#
import pytest, json, time, base64
from pysecp256k1 import tagged_sha256
from bip32 import BIP32Node, ranged_unspendable_internal_key
from constants import BIP_341_H
from helpers import taptweak
import bech32
from test_miniscript import offer_minsc_import, usb_miniscript_addr, get_cc_key


# chain codes of the two unspendable keys, both on the BIP-341 H point
CC_A = 32 * b"\x01"
CC_B = 32 * b"\x02"

# expected index 0 external address of the policies below, as derived by
# Bitcoin Core v31.1 (signet) `deriveaddresses`, simulator default seed
# (xfp 0f056943), own key at m/86h/1h/0h:
#   tr(A/<0;1>/*,{pk(me/<2;3>/*),pk(LEAF)})
CORE_ADDRS = {
    # LEAF = A/<4;5>/*
    "one_nums": "tb1pz5f2mgt3fhwarfdqdxmgmx3872xef5sudp6erevheh5g6gpfc9ts3w2g6n",
    # LEAF = B/<4;5>/*
    "two_nums_disjoint": "tb1py2vqdm9nxfujlxlx9tdx7ngcwk3vs66nwjccknvue2a00unmlqpsmdvsvz",
    # LEAF = B/<0;1>/*
    "two_nums_same_path": "tb1p2kqdcy7h8uqg4uvkhnukly9njsjjhuv0uvcs2tq4d6g4xem78xpsdj6lxp",
}
# Core gives this address for "two_nums_same_path" if LEAF is A/<0;1>/* instead,
# ie. if the leaf key takes the chain code of the internal key
WRONG_ADDR_SAME_PATH = "tb1pr9enf9h0ca3ewmqrw2nn9mj56dwnd84kj4977kwntmwn2xufx6rq648d0a"


def tapleaf_pk(xonly):
    # leaf hash of pk(KEY) tapscript: <KEY> OP_CHECKSIG, leaf version 0xc0
    script = b"\x20" + xonly + b"\xac"
    return tagged_sha256(b"TapLeaf", b"\xc0" + bytes([len(script)]) + script)


def tapbranch(a, b):
    return tagged_sha256(b"TapBranch", b"".join(sorted([a, b])))


def xonly_at(key, path):
    # key is "[orig]xpub/<a;b>/*" or "xpub/<a;b>/*"
    xpub = key.split("]")[-1].split("/")[0]
    return BIP32Node.from_hwif(xpub).subkey_for_path(path).sec()[1:]


def expected_address(ik, leaf0, leaf1, leaf1_branch, idx=0):
    # independent derivation of tr(ik/<0;1>/*,{pk(leaf0/<2;3>/*),pk(leaf1/<N;M>/*)})
    ik_x = xonly_at(ik, f"0/{idx}")
    root = tapbranch(tapleaf_pk(xonly_at(leaf0, f"2/{idx}")),
                     tapleaf_pk(xonly_at(leaf1, f"{leaf1_branch}/{idx}")))
    return bech32.encode("tb", 1, taptweak(ik_x, root))


@pytest.mark.parametrize("case, leaf_cc, leaf_branch", [
    # one unspendable xpub used twice (same chain code, disjoint multipath): control
    ("one_nums", CC_A, 4),
    # two unspendable xpubs, same H pubkey, different chain codes, disjoint multipath
    ("two_nums_disjoint", CC_B, 4),
    # two unspendable xpubs, same H pubkey, different chain codes, same multipath
    ("two_nums_same_path", CC_B, 0),
], ids=["one_nums", "two_nums_disjoint", "two_nums_same_path"])
def test_same_pubkey_diff_chain_code(case, leaf_cc, leaf_branch, get_cc_key, offer_minsc_import,
                                     press_select, usb_miniscript_addr, cap_story,
                                     clear_miniscript, goto_home):
    goto_home()
    clear_miniscript()

    nums_a = ranged_unspendable_internal_key(CC_A, subderiv="/<0;1>/*")
    nums_b = ranged_unspendable_internal_key(leaf_cc,
                                             subderiv=f"/<{leaf_branch};{leaf_branch + 1}>/*")

    # same pubkey (BIP-341 H) for both, chain code differs unless control
    pk_a = BIP32Node.from_hwif(nums_a.split("/")[0]).sec()[1:]
    pk_b = BIP32Node.from_hwif(nums_b.split("/")[0]).sec()[1:]
    assert pk_a == pk_b == bytes.fromhex(BIP_341_H)

    me = get_cc_key("86h/1h/0h", subderiv="/<2;3>/*")
    desc = f"tr({nums_a},{{pk({me}),pk({nums_b})}})"

    expect = expected_address(nums_a, me, nums_b, leaf_branch)
    assert expect == CORE_ADDRS[case]

    _, story = offer_minsc_import(json.dumps({"name": case, "desc": desc}))
    if "Create new miniscript wallet?" not in story:
        # refusing such policy is acceptable, showing a wrong address is not
        assert case != "one_nums", story
        return

    press_select()
    time.sleep(.2)

    addr = usb_miniscript_addr(case, 0, False)
    time.sleep(.1)
    _, story = cap_story()
    assert addr in story
    press_select()

    assert addr != WRONG_ADDR_SAME_PATH
    assert addr == expect


def watch_wallet(bitcoind, name, desc):
    # watch-only Core wallet with the receive and change branches of a <0;1>, <2;3> descriptor
    w = bitcoind.create_wallet(wallet_name=name, disable_private_keys=True, blank=True,
                               passphrase=None, avoid_reuse=False, descriptors=True)
    reqs = []
    for ext, intr in [(0, 2), (1, 3)]:
        d = desc.replace("<0;1>", str(ext)).replace("<2;3>", str(intr))
        d = bitcoind.rpc.getdescriptorinfo(d)["descriptor"]
        reqs.append({"desc": d, "timestamp": 0, "range": [0, 20], "active": False})
    res = w.importdescriptors(reqs)
    assert all(r["success"] for r in res), res
    return w, reqs


def test_wrong_address_coins_recoverable(bitcoind, use_regtest, get_cc_key, offer_minsc_import,
                                         press_select, usb_miniscript_addr, cap_story,
                                         clear_miniscript, goto_home, start_sign, end_sign):
    # coins sent to the wrong address Coldcard shows for two_nums_same_path are not lost:
    # they are locked by Coldcard's view of the descriptor (leaf key B given A's chain code),
    # and Coldcard signs a spend of them through its own leaf
    use_regtest()
    goto_home()
    clear_miniscript()

    nums_a = ranged_unspendable_internal_key(CC_A, subderiv="/<0;1>/*")
    nums_b = ranged_unspendable_internal_key(CC_B, subderiv="/<0;1>/*")
    me = get_cc_key("86h/1h/0h", subderiv="/<2;3>/*")
    real_desc = f"tr({nums_a},{{pk({me}),pk({nums_b})}})"
    # what Coldcard derives: the leaf key B with the chain code of A
    cc_view_desc = f"tr({nums_a},{{pk({me}),pk({nums_a})}})"

    name = "recover"
    _, story = offer_minsc_import(json.dumps({"name": name, "desc": real_desc}))
    if "Create new miniscript wallet?" not in story:
        pytest.skip("policy refused at import, no wrong address to fund")
    press_select()
    time.sleep(.2)
    cc_addr = usb_miniscript_addr(name, 0, False)
    time.sleep(.1)
    press_select()

    real_w, real_reqs = watch_wallet(bitcoind, "real", real_desc)
    view_w, view_reqs = watch_wallet(bitcoind, "ccview", cc_view_desc)
    real_addr = bitcoind.rpc.deriveaddresses(real_reqs[0]["desc"], [0, 0])[0]
    view_addr = bitcoind.rpc.deriveaddresses(view_reqs[0]["desc"], [0, 0])[0]
    print("coldcard address:", cc_addr)
    print("real descriptor address (Core):", real_addr)
    print("coldcard view address (Core):", view_addr)
    assert cc_addr.startswith("bcrt1p")
    assert cc_addr != real_addr
    assert cc_addr == view_addr

    # fund the wrong address
    supply = bitcoind.supply_wallet
    fund_txid = supply.sendtoaddress(cc_addr, 1.0)
    supply.generatetoaddress(1, supply.getnewaddress())
    print("funding txid:", fund_txid)

    # the coordinator holding the real descriptor does not see the coin
    assert real_w.listunspent() == []
    scan_real = bitcoind.rpc.scantxoutset("start", [{"desc": r["desc"], "range": 20}
                                                    for r in real_reqs])
    assert scan_real["unspents"] == []
    scan_view = bitcoind.rpc.scantxoutset("start", [{"desc": r["desc"], "range": 20}
                                                    for r in view_reqs])
    assert [u["txid"] for u in scan_view["unspents"]] == [fund_txid]

    # Coldcard's view of the descriptor sees it, and builds the spend
    utxos = view_w.listunspent()
    assert len(utxos) == 1 and utxos[0]["txid"] == fund_txid
    dest = supply.getnewaddress("", "bech32m")
    resp = view_w.walletcreatefundedpsbt(
        [{"txid": fund_txid, "vout": utxos[0]["vout"]}], [{dest: 1.0}], 0,
        {"fee_rate": 2, "subtractFeeFromOutputs": [0], "add_inputs": False})
    dec = bitcoind.rpc.decodepsbt(resp["psbt"])
    inp = dec["inputs"][0]
    assert inp["taproot_scripts"]
    assert any(d["master_fingerprint"] == "0f056943" for d in inp["taproot_bip32_derivs"])

    start_sign(base64.b64decode(resp["psbt"]))
    signed = end_sign(True)
    signed_b64 = base64.b64encode(signed).decode()
    dec = bitcoind.rpc.decodepsbt(signed_b64)
    assert dec["inputs"][0].get("taproot_script_path_sigs"), "Coldcard did not sign the leaf"

    fin = bitcoind.rpc.finalizepsbt(signed_b64)
    assert fin["complete"]
    # script path spend: signature, the pk(me) leaf script, control block
    wit = bitcoind.rpc.decoderawtransaction(fin["hex"])["vin"][0]["txinwitness"]
    me_x = xonly_at(me, "2/0").hex()
    assert len(wit) == 3 and wit[1] == f"20{me_x}ac", wit
    spend_txid = bitcoind.rpc.sendrawtransaction(fin["hex"])
    supply.generatetoaddress(1, supply.getnewaddress())
    print("spend txid:", spend_txid)

    assert bitcoind.rpc.gettxout(fund_txid, utxos[0]["vout"]) is None
    tx = supply.gettransaction(spend_txid)
    assert tx["confirmations"] == 1
    assert view_w.listunspent() == []
