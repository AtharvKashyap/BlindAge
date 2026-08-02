import binascii
import hashlib
from datetime import datetime, timezone

from blindage.crypto import b64u_decode, verifier_from_issuer_key
from blindage.crypto.bbs import BBS_ALGORITHM, BbsError, bbs_proof_verify
from blindage.registry import TrustRegistry
from blindage.schemas import (
    VC_HEADER,
    Decision,
    IssuerStatus,
    Presentation,
    VcPresentation,
    VerifierDecision,
    VerifierPolicy,
    assurance_at_least,
    token_message,
    vc_presentation_header,
)
from blindage.verifier.challenge import ChallengeManager
from blindage.verifier.replay_cache import ReplayCache


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class BlindAgeVerifier:
    def __init__(
        self,
        registry: TrustRegistry,
        policy: VerifierPolicy,
        replay_cache: ReplayCache,
        challenge_manager: ChallengeManager,
        audience: str,
    ) -> None:
        if policy.maximum_token_age_seconds is not None:
            raise ValueError(
                "maximum_token_age_seconds is not supported in Phase 1 "
                "(tokens carry no issuance timestamp)"
            )
        self._registry = registry
        self._policy = policy
        self._replay = replay_cache
        self._challenges = challenge_manager
        self._audience = audience

    def verify(self, presentation: Presentation) -> VerifierDecision:
        flags = dict(
            signature_valid=False,
            issuer_trusted=False,
            claim_satisfied=False,
            assurance_sufficient=False,
            expired=True,
            replayed=False,
            revoked=True,
            domain_binding_valid=False,
            challenge_valid=False,
        )
        derived_claim = None
        derived_assurance = None
        token = presentation.token

        def deny() -> VerifierDecision:
            return VerifierDecision(
                valid=False,
                claim=derived_claim,
                assurance_level=derived_assurance,
                decision=Decision.DENY,
                **flags,
            )

        issuer = self._registry.get_issuer(token.issuer_id)
        if (
            issuer is None
            or issuer.status != IssuerStatus.ACTIVE
            or token.issuer_id not in self._policy.trusted_issuers
        ):
            return deny()
        flags["issuer_trusted"] = True
        flags["revoked"] = False

        key = self._registry.get_token_key(token.issuer_id, token.issuer_key_id)
        if key is None:
            return deny()

        if key.algorithm not in self._policy.allowed_algorithms:
            return deny()

        try:
            verifier = verifier_from_issuer_key(key)
            flags["signature_valid"] = verifier.verify(
                token_message(token.nonce), b64u_decode(token.signature)
            )
        except (binascii.Error, ValueError):
            # Covers malformed base64 signatures AND UnsupportedAlgorithmError
            # (a ValueError subclass): both deny cleanly.
            flags["signature_valid"] = False
        if not flags["signature_valid"]:
            return deny()

        # MOD-1: authoritative claim/assurance/epoch come from the registry
        # binding of the verifying key. Advisory token fields must agree.
        derived_claim = key.claim
        derived_assurance = key.assurance_level
        if (token.claim, token.assurance_level, token.epoch) != (
            key.claim,
            key.assurance_level,
            key.epoch,
        ):
            return deny()

        flags["claim_satisfied"] = derived_claim == self._policy.required_claim
        flags["assurance_sufficient"] = assurance_at_least(
            derived_assurance, self._policy.minimum_assurance_level
        )
        if not (flags["claim_satisfied"] and flags["assurance_sufficient"]):
            return deny()

        now = datetime.now(timezone.utc)
        flags["expired"] = not (key.valid_from <= now <= key.valid_until)
        if flags["expired"]:
            return deny()

        binding = presentation.domain_binding
        if self._policy.require_domain_binding:
            flags["domain_binding_valid"] = binding.audience == self._audience
            if not flags["domain_binding_valid"]:
                return deny()

            challenge = self._challenges.consume(binding.challenge_id, binding.challenge)
            flags["challenge_valid"] = (
                challenge is not None
                and challenge.required_claim == self._policy.required_claim
            )
            if not flags["challenge_valid"]:
                return deny()
        else:
            flags["domain_binding_valid"] = True
            flags["challenge_valid"] = True

        # Replay check LAST: the nonce is only burned once every other check
        # has passed, so a failed attempt does not consume the token.
        if self._policy.require_single_use:
            if not self._replay.check_and_insert(sha256_hex(token.nonce)):
                flags["replayed"] = True
                return deny()

        return VerifierDecision(
            valid=True,
            claim=derived_claim,
            assurance_level=derived_assurance,
            decision=Decision.ALLOW,
            **flags,
        )


def verify_vc_presentation(
    presentation: VcPresentation,
    registry: TrustRegistry,
    trusted_issuer: str,
    audience: str,
    challenge_store: ChallengeManager,
) -> VerifierDecision:
    """Verify a reusable-credential selective-disclosure presentation.

    Mirrors ``BlindAgeVerifier.verify``'s decision/reason structure. The
    authoritative assurance/epoch come from the registry's ``vc_signing`` key
    binding (key partitioning), never the token body; the revealed claim is the
    single message the wallet disclosed. Single-use is enforced by the
    one-time challenge (there is no per-token nonce), so ``replayed`` stays
    ``False`` — a burned challenge surfaces as ``challenge_valid=False``.
    """
    flags = dict(
        signature_valid=False,
        issuer_trusted=False,
        claim_satisfied=False,
        assurance_sufficient=False,
        expired=True,
        replayed=False,
        revoked=True,
        domain_binding_valid=False,
        challenge_valid=False,
    )
    derived_claim = None
    derived_assurance = None

    def deny() -> VerifierDecision:
        return VerifierDecision(
            valid=False,
            claim=derived_claim,
            assurance_level=derived_assurance,
            decision=Decision.DENY,
            **flags,
        )

    issuer = registry.get_issuer(presentation.issuer_id)
    if (
        issuer is None
        or issuer.status != IssuerStatus.ACTIVE
        or presentation.issuer_id != trusted_issuer
    ):
        return deny()
    flags["issuer_trusted"] = True
    flags["revoked"] = False

    key = registry.get_vc_key(presentation.issuer_id, presentation.issuer_key_id)
    if key is None:
        return deny()
    if key.algorithm != BBS_ALGORITHM:  # algorithm allowlist
        return deny()

    # A well-formed VC presentation discloses exactly the three fixed metadata
    # messages plus one claim, at indexes [0, 1, 2, claim_index]. Reject any
    # other index shape so a malicious wallet cannot play index games.
    disclosed_indexes = presentation.disclosed_indexes
    if len(disclosed_indexes) != 4 or disclosed_indexes[:3] != [0, 1, 2]:
        return deny()

    # Authoritative assurance/epoch come from the registry key binding; the
    # advisory presentation fields must agree.
    derived_assurance = key.assurance_level
    if (presentation.assurance_level, presentation.epoch) != (
        key.assurance_level,
        key.epoch,
    ):
        return deny()
    derived_claim = presentation.required_claim

    now = datetime.now(timezone.utc)
    flags["expired"] = not (key.valid_from <= now <= key.valid_until)
    if flags["expired"]:
        return deny()

    binding = presentation.domain_binding
    flags["domain_binding_valid"] = binding.audience == audience
    if not flags["domain_binding_valid"]:
        return deny()

    challenge = challenge_store.consume(binding.challenge_id, binding.challenge)
    flags["challenge_valid"] = (
        challenge is not None
        and challenge.required_claim == presentation.required_claim
    )
    if not flags["challenge_valid"]:
        return deny()

    flags["claim_satisfied"] = challenge.required_claim == presentation.required_claim
    flags["assurance_sufficient"] = assurance_at_least(
        derived_assurance, challenge.minimum_assurance_level
    )
    if not (flags["claim_satisfied"] and flags["assurance_sufficient"]):
        return deny()

    # Reconstruct the disclosed messages from the authoritative registry binding
    # and the revealed claim, in the fixed order the wallet signed/disclosed.
    disclosed_messages = [
        presentation.issuer_id.encode("utf-8"),
        key.assurance_level.value.encode("utf-8"),
        key.epoch.encode("utf-8"),
        presentation.required_claim.value.encode("utf-8"),
    ]
    ph = vc_presentation_header(binding)
    try:
        flags["signature_valid"] = bbs_proof_verify(
            key.public_key,
            b64u_decode(presentation.proof),
            VC_HEADER,
            ph,
            disclosed_messages,
            disclosed_indexes,
        )
    except (BbsError, binascii.Error, ValueError):
        flags["signature_valid"] = False
    if not flags["signature_valid"]:
        return deny()

    return VerifierDecision(
        valid=True,
        claim=derived_claim,
        assurance_level=derived_assurance,
        decision=Decision.ALLOW,
        **flags,
    )
