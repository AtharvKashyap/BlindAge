// Pure protocol logic for the BlindAge extension. NO chrome.* or window.*
// references — this module is unit-tested under Node and imported by both the
// service worker and the popup. The extension performs NO cryptography; a
// presentation only carries an already-signed token plus a fresh domain binding.

export const AGE_CLAIMS = ["AGE_OVER_13", "AGE_OVER_16", "AGE_OVER_18", "AGE_OVER_21"];
const ASSURANCE_ORDER = { AAL0: 0, AAL1: 1, AAL2: 2, AAL3: 3 };

export function assuranceAtLeast(level, minimum) {
  return (ASSURANCE_ORDER[level] ?? -1) >= (ASSURANCE_ORDER[minimum] ?? 99);
}

export function normalizeOrigin(hostOrUrl) {
  let host = String(hostOrUrl).trim();
  if (host.includes("://")) {
    try {
      host = new URL(host).hostname;
    } catch {
      /* fall through */
    }
  } else {
    host = host.split("/")[0].split(":")[0];
  }
  return host.toLowerCase();
}

export function validateChallenge(challenge, pageHost, nowMs = Date.now()) {
  const required = [
    "challenge_id",
    "required_claim",
    "minimum_assurance_level",
    "audience",
    "challenge",
    "expires_at",
  ];
  for (const field of required) {
    if (!challenge || challenge[field] == null) {
      return { ok: false, reason: `missing field: ${field}` };
    }
  }
  if (!AGE_CLAIMS.includes(challenge.required_claim)) {
    return { ok: false, reason: `unknown claim: ${challenge.required_claim}` };
  }
  if (!(challenge.minimum_assurance_level in ASSURANCE_ORDER)) {
    return { ok: false, reason: `unknown assurance level: ${challenge.minimum_assurance_level}` };
  }
  if (normalizeOrigin(challenge.audience) !== normalizeOrigin(pageHost)) {
    return { ok: false, reason: `audience ${challenge.audience} does not match page ${pageHost}` };
  }
  const expiresMs = Date.parse(challenge.expires_at);
  if (!Number.isFinite(expiresMs) || expiresMs <= nowMs) {
    return { ok: false, reason: "challenge expired" };
  }
  return { ok: true };
}

export function selectToken(tokens, challenge) {
  for (const t of tokens || []) {
    if (t.spent) continue;
    if (t.claim !== challenge.required_claim) continue;
    if (!assuranceAtLeast(t.assurance_level, challenge.minimum_assurance_level)) continue;
    return t;
  }
  return null;
}

export function buildPresentation(token, challenge, nowIso = new Date().toISOString()) {
  return {
    version: "1.0",
    presentation_type: "blindage.age_token",
    required_claim: challenge.required_claim,
    token: {
      version: token.version ?? "1.0",
      claim: token.claim,
      assurance_level: token.assurance_level,
      epoch: token.epoch,
      issuer_id: token.issuer_id,
      issuer_key_id: token.issuer_key_id,
      nonce: token.nonce,
      signature: token.signature,
    },
    domain_binding: {
      audience: challenge.audience,
      challenge: challenge.challenge,
      challenge_id: challenge.challenge_id,
      timestamp: nowIso,
    },
  };
}

export function isValidToken(t) {
  if (!t || typeof t !== "object") return false;
  if (!AGE_CLAIMS.includes(t.claim)) return false;
  if (!(t.assurance_level in ASSURANCE_ORDER)) return false;
  const requiredStrings = ["nonce", "signature", "epoch", "issuer_id", "issuer_key_id"];
  for (const field of requiredStrings) {
    if (typeof t[field] !== "string" || t[field].length === 0) return false;
  }
  return true;
}

export function consentSummary(challenge, siteHost) {
  return {
    site: normalizeOrigin(siteHost),
    claim: challenge.required_claim,
    assurance: challenge.minimum_assurance_level,
    willReceive: [
      `Age threshold satisfied: ${challenge.required_claim}`,
      `Assurance level: ${challenge.minimum_assurance_level}`,
      "The issuing organization and token validity",
    ],
    willNotReceive: [
      "Your name",
      "Your exact date of birth",
      "Your address or government ID",
      "Your identity or any account linking you across sites",
    ],
  };
}
