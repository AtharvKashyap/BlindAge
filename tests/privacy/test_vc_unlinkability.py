"""Value-level unlinkability for BBS selective-disclosure VC presentations.

Two presentations of the *same* credential must share no byte-strings beyond the
intentionally revealed fields; hidden claims must never appear anywhere in a
serialized presentation; and neither the credential signature nor the issuer
public key (wallet-side trust data) may leak into what the site receives.

These are product requirements (constitution rules 1, 6) and are CI-blocking.
"""
import json

from blindage.wallet.client import vc_prove
from tests.integration.test_vc_flow import _challenge, _stack

# Fields a VcPresentation intentionally reveals. These legitimately repeat across
# two presentations of the same credential for the same claim: the credential
# metadata the site needs to look up the registry key (issuer_id/key_id, epoch,
# assurance, claim) plus the disclosure structure itself (disclosed_indexes is
# exactly [0, 1, 2, claim_index] — the same claim always discloses the same
# indexes; that is disclosure, not correlatable leakage).
REVEALED_KEYS = {
    "version",
    "presentation_type",
    "required_claim",
    "issuer_id",
    "issuer_key_id",
    "assurance_level",
    "epoch",
    "disclosed_indexes",
}


def test_presentations_share_no_correlatable_values():
    site, cred = _stack()
    p1 = json.loads(vc_prove(cred, _challenge(site)).model_dump_json())
    p2 = json.loads(vc_prove(cred, _challenge(site)).model_dump_json())
    # proof and domain_binding (fresh challenge) must differ entirely
    assert p1["proof"] != p2["proof"]
    assert p1["domain_binding"] != p2["domain_binding"]
    # nothing outside the intentionally revealed fields may repeat
    varying1 = {k: v for k, v in p1.items() if k not in REVEALED_KEYS}
    varying2 = {k: v for k, v in p2.items() if k not in REVEALED_KEYS}
    for k in varying1:
        if k == "domain_binding":
            assert varying1[k]["challenge"] != varying2[k]["challenge"]
        else:
            assert varying1[k] != varying2[k], k
    # the credential's signature itself never appears in a presentation
    assert cred.signature not in json.dumps(p1)
    # nor does the issuer public key: VcPresentation carries no issuer_public_key
    # field (the verifier looks the key up in the registry), so this wallet-side
    # trust datum must be absent from what the site receives.
    assert cred.issuer_public_key not in json.dumps(p1)
    assert "issuer_public_key" not in p1


def test_hidden_claims_absent_from_presentation():
    site, cred = _stack()
    p = vc_prove(cred, _challenge(site))
    hidden = {c.value for c in cred.claims} - {p.required_claim.value}
    serialized = p.model_dump_json()
    for claim in hidden:
        assert claim not in serialized
