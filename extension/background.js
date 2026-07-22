// Thin MV3 service-worker glue. All decision logic lives in core/*.js (tested
// under Node). This file only bridges chrome.storage + chrome.runtime messaging.
import { validateChallenge, consentSummary } from "./core/protocol.js";
import { mergeTokens, approveRequest } from "./core/store.js";

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
