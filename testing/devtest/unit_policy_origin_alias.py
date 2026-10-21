# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import ngu, chains
from desc_utils import ExtendedKey, bip388_validate_policy, bip388_wallet_policy_to_descriptor
from descriptor import Descriptor
from stash import SensitiveValues
from utils import swab32, xfp2str

with SensitiveValues() as sv:
    mine = chains.current_key_chain().serialize_public(sv.node)

# The same foreign signing node can have accepted, distinct origin paths;
# only the first path is derived here, while the second may be fabricated.
foreign = ngu.hdnode.HDNode().from_master(bytes(range(32)))
foreign_fp = xfp2str(swab32(foreign.my_fp()))
foreign.derive(7, False)
foreign.derive(8, False)
assert foreign.depth() >= 2
foreign_xpub = chains.current_key_chain().serialize_public(foreign)
assert foreign_xpub != mine
assert ExtendedKey.from_string(foreign_xpub).origin.cc_fp != \
    ExtendedKey.from_string(mine).origin.cc_fp
first = "[%s/7/8]%s" % (foreign_fp, foreign_xpub)
second = "[%s/9/10]%s" % (foreign_fp, foreign_xpub)
desc = Descriptor.from_string("tr(%s/<0;1>/*,{pk(%s/<2;3>/*),pk(%s/<4;5>/*)})" %
                              (mine, first, second))
desc.validate()
template, info = desc.bip388_wallet_policy()
assert len(info) == 2
assert foreign_xpub not in template, template
assert mine not in template, template
bip388_validate_policy(template.encode(), info)
restored = Descriptor.from_string(bip388_wallet_policy_to_descriptor(template, info))
for change in (False, True):
    for index in (0, 7):
        assert restored.derive(None, change=change).derive(index).script_pubkey() == \
            desc.derive(None, change=change).derive(index).script_pubkey()
