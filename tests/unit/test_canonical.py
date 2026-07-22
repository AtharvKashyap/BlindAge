from blindage.canonical import canonical_json_bytes
from blindage.schemas import AgeClaim, AssuranceLevel, VerifierPolicy


def test_sorted_keys_no_whitespace():
    assert canonical_json_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_unicode_not_escaped():
    assert canonical_json_bytes({"k": "café"}) == '{"k":"café"}'.encode("utf-8")


def test_deterministic_across_key_order():
    assert canonical_json_bytes({"x": [1, 2], "a": {"z": 1, "y": 2}}) == canonical_json_bytes(
        {"a": {"y": 2, "z": 1}, "x": [1, 2]}
    )


def test_model_none_fields_excluded():
    p = VerifierPolicy(
        policy_id="p1",
        required_claim=AgeClaim.AGE_OVER_18,
        minimum_assurance_level=AssuranceLevel.AAL2,
        trusted_issuers=[],
    )
    out = canonical_json_bytes(p)
    assert b"maximum_token_age_seconds" not in out
    assert b'"required_claim":"AGE_OVER_18"' in out
