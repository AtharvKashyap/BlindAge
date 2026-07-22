import { selectToken, buildPresentation, isValidToken } from "./protocol.js";

export function mergeTokens(existing, incoming) {
  const byNonce = new Map((existing || []).map((t) => [t.nonce, t]));
  let added = 0;
  for (const t of incoming || []) {
    if (!isValidToken(t)) continue;
    if (!byNonce.has(t.nonce)) {
      byNonce.set(t.nonce, { ...t, spent: t.spent ?? false });
      added += 1;
    }
  }
  return { tokens: [...byNonce.values()], added };
}

export function approveRequest(tokens, challenge, nowIso) {
  const chosen = selectToken(tokens, challenge);
  if (!chosen) return { error: `no unspent token for ${challenge.required_claim}` };
  const presentation = buildPresentation(chosen, challenge, nowIso);
  const updated = tokens.map((t) => (t.nonce === chosen.nonce ? { ...t, spent: true } : t));
  return { presentation, tokens: updated };
}
