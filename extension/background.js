// Thin MV3 service-worker glue. All decision logic lives in core/*.js (tested
// under Node). This file only bridges chrome.storage + chrome.runtime messaging.
import { validateChallenge, consentSummary } from "./core/protocol.js";
import { mergeTokens, approveRequest } from "./core/store.js";
import { RSABSSA_ALGORITHM, importRsaPublicKey } from "./core/rsabssa.js";
import { findTokenKey, prepareBlindBatch, assembleTokens } from "./core/mint.js";

const pending = {}; // tabId -> { challenge, pageHost }

async function getTokens() {
  const { tokens } = await chrome.storage.local.get({ tokens: [] });
  return tokens;
}
async function setTokens(tokens) {
  await chrome.storage.local.set({ tokens });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === "import_tokens") {
      const { tokens, added, rejected } = mergeTokens(await getTokens(), msg.tokens);
      await setTokens(tokens);
      sendResponse({ count: tokens.length, added, rejected });
    } else if (msg.type === "mint") {
      try {
        const wk = await (await fetch(`${msg.issuer}/.well-known/blindage-issuer.json`)).json();
        const key = findTokenKey(wk, msg.claim, msg.assuranceLevel, msg.epoch);
        if (!key) { sendResponse({ ok: false, reason: "issuer advertises no matching key" }); return; }
        if (key.algorithm !== RSABSSA_ALGORITHM) {
          sendResponse({ ok: false, reason: `unsupported key algorithm ${key.algorithm}` }); return;
        }
        const pub = await importRsaPublicKey(key.public_key);
        const { nonces, invs, blindedB64u } = await prepareBlindBatch(pub, msg.count);
        const issueResp = await fetch(`${msg.issuer}/v1/tokens/issue`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            version: "1.0", enrollment_id: msg.enrollmentId, claim: msg.claim,
            assurance_level: msg.assuranceLevel, epoch: msg.epoch, blinded_messages: blindedB64u,
          }),
        });
        if (!issueResp.ok) {
          sendResponse({ ok: false, reason: `issuer returned ${issueResp.status}` }); return;
        }
        const body = await issueResp.json();
        const tokens = await assembleTokens({
          pub, nonces, invs, signaturesB64u: body.signatures, claim: msg.claim,
          assuranceLevel: msg.assuranceLevel, epoch: msg.epoch,
          issuerId: wk.issuer_id, keyId: key.key_id,
        });
        const merged = mergeTokens(await getTokens(), tokens);
        await setTokens(merged.tokens);
        sendResponse({ ok: true, added: merged.added, total: merged.tokens.length });
      } catch (e) {
        sendResponse({ ok: false, reason: String((e && e.message) || e) });
      }
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
    } else {
      sendResponse({ ok: false, reason: "unknown message type" });
    }
  })();
  return true; // async sendResponse
});
