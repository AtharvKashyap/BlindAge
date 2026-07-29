// Thin MV3 service-worker glue. All decision logic lives in core/*.js (tested
// under Node). This file only bridges chrome.storage + chrome.runtime messaging.
import { validateChallenge, consentSummary } from "./core/protocol.js";
import { mergeTokens, approveRequest } from "./core/store.js";
import { RSABSSA_ALGORITHM, importRsaPublicKey } from "./core/rsabssa.js";
import { findTokenKey, prepareBlindBatch, assembleTokens } from "./core/mint.js";
import {
  DEFAULT_CLAIM, DEFAULT_ASSURANCE, DEFAULT_COUNT,
  issuerOrigin, validIssuerRecord, matchPendingEnroll, pickLatestKey,
} from "./core/onboard.js";
import {
  RegistryError, verifyRegistry, approvedIssuers, isRollback, registryKeyFor,
  topUpPlan, TOPUP_THRESHOLD,
} from "./core/registry.js";

const pending = {}; // tabId -> { challenge, pageHost }

async function getLocal(key, fallback) {
  const o = await chrome.storage.local.get({ [key]: fallback });
  return o[key];
}
async function getTokens() { return getLocal("tokens", []); }
async function setTokens(tokens) { await chrome.storage.local.set({ tokens }); }

// Fetch + verify the signed registry, reject rollbacks, cache the verified copy.
// A registry fetch carries nothing but the GET itself (no identity, no domain).
// If the mirror is down or the payload is bad, keep serving the cached verified
// copy (marked stale); with no cache at all, callers fail closed.
async function refreshRegistry() {
  const trust = await getLocal("trust", null);
  if (!trust || !trust.registryUrl || !trust.rootKey) {
    return { ok: false, reason: "trust settings not configured" };
  }
  const cached = await getLocal("registryCache", null);
  try {
    const [regResp, sigResp] = await Promise.all([
      fetch(`${trust.registryUrl}/registry.json`),
      fetch(`${trust.registryUrl}/registry.sig`),
    ]);
    if (!regResp.ok || !sigResp.ok) {
      throw new Error(`mirror returned ${regResp.status}/${sigResp.status}`);
    }
    const registry = await verifyRegistry(
      await regResp.text(), (await sigResp.text()).trim(), trust.rootKey
    );
    if (cached && isRollback(cached.generatedAt, registry)) {
      return { ok: false, reason: "registry rollback rejected — keeping cached copy" };
    }
    await chrome.storage.local.set({
      registryCache: {
        registry, generatedAt: registry.generated_at, fetchedAt: Date.now(),
      },
    });
    return {
      ok: true,
      generatedAt: registry.generated_at,
      issuers: approvedIssuers(registry, new Date().toISOString()).length,
    };
  } catch (e) {
    if (cached) {
      // Mirror down or bad payload: keep serving the cached verified copy.
      return { ok: true, stale: true, generatedAt: cached.generatedAt,
               reason: String((e && e.message) || e) };
    }
    return { ok: false, reason: String((e && e.message) || e) };
  }
}

// Returns null when approved, otherwise a refusal reason (fail closed).
async function registryRefusal(wk, key) {
  const cache = await getLocal("registryCache", null);
  if (!cache || !cache.registry) {
    return "no verified trust registry — check Trust settings";
  }
  const approved = approvedIssuers(cache.registry, new Date().toISOString());
  if (!approved.some((i) => i.issuer_id === wk.issuer_id)) {
    return `issuer ${wk.issuer_id} is not registry-approved`;
  }
  const regKey = registryKeyFor(cache.registry, wk.issuer_id, key.key_id);
  if (!regKey) return `issuer key ${key.key_id} is not in the registry`;
  if (
    regKey.public_key !== key.public_key ||
    regKey.algorithm !== key.algorithm ||
    regKey.claim !== key.claim ||
    regKey.assurance_level !== key.assurance_level ||
    regKey.epoch !== key.epoch
  ) {
    return `issuer key ${key.key_id} does not match the registry entry`;
  }
  return null;
}

// Blind-mint a batch. POSTs ONLY blinded_messages to the issuer — nonces,
// blinding inverses, and final signatures never leave the extension.
async function doMint({ issuer, enrollmentId, claim, assuranceLevel, epoch, count }) {
  const wk = await (await fetch(`${issuer}/.well-known/blindage-issuer.json`)).json();
  const key = epoch
    ? findTokenKey(wk, claim, assuranceLevel, epoch)
    : pickLatestKey(wk, claim, assuranceLevel);
  if (!key) return { ok: false, reason: "issuer advertises no matching key" };
  if (key.algorithm !== RSABSSA_ALGORITHM) {
    return { ok: false, reason: `unsupported key algorithm ${key.algorithm}` };
  }
  const refusal = await registryRefusal(wk, key);
  if (refusal) return { ok: false, reason: refusal };
  const pub = await importRsaPublicKey(key.public_key);
  const { nonces, invs, blindedB64u } = await prepareBlindBatch(pub, count);
  const issueResp = await fetch(`${issuer}/v1/tokens/issue`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      version: "1.0", enrollment_id: enrollmentId, claim,
      assurance_level: assuranceLevel, epoch: key.epoch, blinded_messages: blindedB64u,
    }),
  });
  if (!issueResp.ok) return { ok: false, reason: `issuer returned ${issueResp.status}` };
  const body = await issueResp.json();
  const tokens = await assembleTokens({
    pub, nonces, invs, signaturesB64u: body.signatures, claim,
    assuranceLevel, epoch: key.epoch, issuerId: wk.issuer_id, keyId: key.key_id,
  });
  const merged = mergeTokens(await getTokens(), tokens);
  await setTokens(merged.tokens);
  return { ok: true, added: merged.added, total: merged.tokens.length };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === "import_tokens") {
      const { tokens, added, rejected } = mergeTokens(await getTokens(), msg.tokens);
      await setTokens(tokens);
      sendResponse({ count: tokens.length, added, rejected });
    } else if (msg.type === "mint") {
      try {
        sendResponse(await doMint({
          issuer: msg.issuer, enrollmentId: msg.enrollmentId, claim: msg.claim,
          assuranceLevel: msg.assuranceLevel, epoch: msg.epoch, count: msg.count,
        }));
      } catch (e) {
        sendResponse({ ok: false, reason: String((e && e.message) || e) });
      }
    } else if (msg.type === "start_enroll") {
      try {
        issuerOrigin(msg.issuer); // throws on invalid/non-http(s)
        const wk = await (await fetch(`${msg.issuer}/.well-known/blindage-issuer.json`)).json();
        const key = pickLatestKey(wk, DEFAULT_CLAIM, DEFAULT_ASSURANCE);
        if (!key) {
          sendResponse({ ok: false, reason: "issuer advertises no AGE_OVER_18 blind key" });
          return;
        }
        const refusal = await registryRefusal(wk, key);
        if (refusal) { sendResponse({ ok: false, reason: refusal }); return; }
        await chrome.storage.local.set({
          pendingEnroll: { issuer: msg.issuer, issuerId: wk.issuer_id, createdAt: Date.now() },
        });
        await chrome.tabs.create({ url: `${msg.issuer}/enroll` });
        sendResponse({ ok: true });
      } catch (e) {
        sendResponse({ ok: false, reason: String((e && e.message) || e) });
      }
    } else if (msg.type === "enrollment") {
      const pe = await getLocal("pendingEnroll", null);
      const verdict = matchPendingEnroll(
        pe, msg.pageOrigin,
        { issuer_id: msg.issuerId, enrollment_id: msg.enrollmentId }, Date.now(),
      );
      if (!verdict.ok) { sendResponse({ ok: false, reason: verdict.reason }); return; }
      await chrome.storage.local.set({ pendingEnroll: null });
      const record = {
        baseUrl: pe.issuer, issuerId: msg.issuerId,
        enrollmentId: msg.enrollmentId, enrolledAt: new Date().toISOString(),
      };
      const issuers = (await getLocal("issuers", [])).filter((r) => r.baseUrl !== record.baseUrl);
      issuers.push(record);
      await chrome.storage.local.set({ issuers });
      let mint;
      try {
        mint = await doMint({
          issuer: pe.issuer, enrollmentId: msg.enrollmentId,
          claim: DEFAULT_CLAIM, assuranceLevel: DEFAULT_ASSURANCE, count: DEFAULT_COUNT,
        });
      } catch (e) {
        mint = { ok: false, reason: String((e && e.message) || e) };
      }
      await chrome.storage.local.set({ lastOnboard: { issuer: pe.issuer, mint, at: Date.now() } });
      sendResponse({ ok: true, mint });
    } else if (msg.type === "list_issuers") {
      sendResponse({ issuers: (await getLocal("issuers", [])).filter(validIssuerRecord) });
    } else if (msg.type === "get_onboard_status") {
      sendResponse({ lastOnboard: await getLocal("lastOnboard", null) });
    } else if (msg.type === "list_tokens") {
      sendResponse({ tokens: await getTokens() });
    } else if (msg.type === "page_request") {
      const check = validateChallenge(msg.challenge, msg.pageHost);
      if (!check.ok) { sendResponse({ ok: false, reason: check.reason }); return; }
      const tabId = sender.tab && sender.tab.id;
      pending[tabId] = { challenge: msg.challenge, pageHost: msg.pageHost };
      chrome.action.setBadgeText({ tabId, text: "1" });
      sendResponse({ ok: true });
    } else if (msg.type === "get_pending") {
      const p = pending[msg.tabId];
      sendResponse(p ? { pending: p, consent: consentSummary(p.challenge, p.pageHost) } : { pending: null });
    } else if (msg.type === "approve") {
      const p = pending[msg.tabId];
      if (!p) { sendResponse({ ok: false, reason: "no pending request" }); return; }
      const result = approveRequest(await getTokens(), p.challenge, new Date().toISOString());
      if (result.error) { sendResponse({ ok: false, reason: result.error }); return; }
      await setTokens(result.tokens);
      delete pending[msg.tabId];
      chrome.action.setBadgeText({ tabId: msg.tabId, text: "" });
      await chrome.tabs.sendMessage(msg.tabId, { type: "deliver_presentation", presentation: result.presentation });
      sendResponse({ ok: true });
    } else if (msg.type === "set_trust") {
      await chrome.storage.local.set({
        trust: { registryUrl: msg.registryUrl, rootKey: msg.rootKey },
      });
      sendResponse(await refreshRegistry());
    } else if (msg.type === "refresh_registry") {
      sendResponse(await refreshRegistry());
    } else if (msg.type === "get_registry") {
      const cache = await getLocal("registryCache", null);
      sendResponse({ registry: (cache && cache.registry) || null });
    } else if (msg.type === "auto_topup") {
      const tokens = await getTokens();
      const issuers = (await getLocal("issuers", [])).filter(validIssuerRecord);
      const plan = topUpPlan(tokens, issuers, {
        claim: DEFAULT_CLAIM, threshold: TOPUP_THRESHOLD, batch: DEFAULT_COUNT,
      });
      const results = [];
      for (const step of plan) {
        try {
          const r = await doMint({
            issuer: step.issuer.baseUrl, enrollmentId: step.issuer.enrollmentId,
            claim: DEFAULT_CLAIM, assuranceLevel: DEFAULT_ASSURANCE, count: step.count,
          });
          results.push({ issuer: step.issuer.baseUrl, ...r });
        } catch (e) {
          results.push({
            issuer: step.issuer.baseUrl, ok: false,
            reason: String((e && e.message) || e),
          });
        }
      }
      sendResponse({ results });
    } else {
      sendResponse({ ok: false, reason: "unknown message type" });
    }
  })();
  return true; // async sendResponse
});
