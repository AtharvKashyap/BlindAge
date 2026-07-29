// extension/popup.js
import { tokensFromParsed } from "./core/protocol.js";
import { approvedIssuers } from "./core/registry.js";

function send(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));
}
async function activeTabId() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab && tab.id;
}

async function renderInventory() {
  const { tokens } = await send({ type: "list_tokens" });
  const counts = {};
  for (const t of tokens || []) {
    if (t.spent) continue;
    counts[t.claim] = (counts[t.claim] || 0) + 1;
  }
  const el = document.getElementById("inventory");
  const entries = Object.entries(counts);
  el.textContent = "";
  if (!entries.length) {
    const small = document.createElement("small");
    small.textContent = "none — get tokens below";
    el.appendChild(small);
    return;
  }
  for (const [claim, count] of entries) {
    const row = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = String(count);
    row.appendChild(document.createTextNode(`${claim}: `));
    row.appendChild(strong);
    row.appendChild(document.createTextNode(" unused"));
    el.appendChild(row);
  }
}

async function renderPending() {
  const tabId = await activeTabId();
  const res = await send({ type: "get_pending", tabId });
  const el = document.getElementById("pending");
  if (!res || !res.pending) { el.textContent = ""; return; }
  const c = res.consent;
  el.textContent = "";

  const card = document.createElement("div");
  card.className = "card consent";

  const siteStrong = document.createElement("strong");
  siteStrong.textContent = c.site;
  const claimStrong = document.createElement("strong");
  claimStrong.textContent = c.claim;
  card.appendChild(siteStrong);
  card.appendChild(document.createTextNode(" requests proof of "));
  card.appendChild(claimStrong);
  card.appendChild(document.createTextNode(` (min assurance ${c.assurance}).`));

  const recv = document.createElement("div");
  recv.className = "recv";
  recv.appendChild(document.createTextNode("Will receive:"));
  const recvUl = document.createElement("ul");
  for (const x of c.willReceive) {
    const li = document.createElement("li");
    li.textContent = x;
    recvUl.appendChild(li);
  }
  recv.appendChild(recvUl);
  card.appendChild(recv);

  const norecv = document.createElement("div");
  norecv.className = "norecv";
  norecv.appendChild(document.createTextNode("Will NOT receive:"));
  const norecvUl = document.createElement("ul");
  for (const x of c.willNotReceive) {
    const li = document.createElement("li");
    li.textContent = x;
    norecvUl.appendChild(li);
  }
  norecv.appendChild(norecvUl);
  card.appendChild(norecv);

  const allowBtn = document.createElement("button");
  allowBtn.id = "allowBtn";
  allowBtn.textContent = "Allow once";
  card.appendChild(allowBtn);

  const allowMsg = document.createElement("div");
  allowMsg.id = "allowMsg";
  card.appendChild(allowMsg);

  el.appendChild(card);

  document.getElementById("allowBtn").addEventListener("click", async () => {
    const r = await send({ type: "approve", tabId });
    document.getElementById("allowMsg").textContent = r.ok ? "Sent ✓" : "Failed: " + r.reason;
    if (r.ok) { renderInventory(); setTimeout(renderPending, 400); }
  });
}

async function importFromText(text, msgEl) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    msgEl.textContent = "Invalid JSON — paste the whole tokens.json, or use Choose file.";
    return;
  }
  const tokens = tokensFromParsed(parsed);
  if (tokens.length === 0) {
    msgEl.textContent = "No tokens found in that JSON (expected a 'tokens' array).";
    return;
  }
  const r = await send({ type: "import_tokens", tokens });
  const parts = [`${r.added} new`, `${r.count} total`];
  if (r.rejected) parts.push(`${r.rejected} rejected as malformed`);
  msgEl.textContent = "Imported. " + parts.join(", ") + ".";
  renderInventory();
}

document.getElementById("importBtn").addEventListener("click", () => {
  importFromText(document.getElementById("importText").value, document.getElementById("importMsg"));
});

document.getElementById("importFile").addEventListener("change", (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => importFromText(String(reader.result), document.getElementById("importMsg"));
  reader.readAsText(file);
});

function syncIssuerControls(issuers) {
  const sel = document.getElementById("issuerSelect");
  const enrolled = issuers.find((r) => r.baseUrl === sel.value);
  // A non-empty selection (enrolled record OR a registry endpoint) fills the
  // issuer URL; "New issuer…" (value "") leaves the manual field untouched.
  if (sel.value) document.getElementById("mIssuer").value = sel.value;
  // Top-up only makes sense once enrolled; registry-only entries keep it hidden.
  document.getElementById("topup").hidden = !enrolled;
}

async function renderIssuers() {
  const { issuers } = await send({ type: "list_issuers" });
  const enrolled = issuers || [];
  const sel = document.getElementById("issuerSelect");
  sel.textContent = "";
  const optNew = document.createElement("option");
  optNew.value = "";
  optNew.textContent = "New issuer…";
  sel.appendChild(optNew);
  for (const rec of enrolled) {
    const o = document.createElement("option");
    o.value = rec.baseUrl;
    o.textContent = rec.baseUrl;
    sel.appendChild(o);
  }
  // Also offer registry-approved issuers the user hasn't enrolled with yet.
  const { registry } = await send({ type: "get_registry" });
  const enrolledUrls = new Set(enrolled.map((r) => r.baseUrl));
  for (const i of approvedIssuers(registry, new Date().toISOString())) {
    if (!i.endpoint || enrolledUrls.has(i.endpoint)) continue;
    const o = document.createElement("option");
    o.value = i.endpoint;
    o.textContent = `${i.endpoint} (registry)`;
    sel.appendChild(o);
  }
  if (enrolled.length) sel.value = enrolled[enrolled.length - 1].baseUrl;
  sel.addEventListener("change", () => syncIssuerControls(enrolled));
  syncIssuerControls(enrolled);
}

async function renderOnboardStatus() {
  const { lastOnboard } = await send({ type: "get_onboard_status" });
  if (!lastOnboard) return;
  const el = document.getElementById("onboardMsg");
  const m = lastOnboard.mint;
  el.textContent = m && m.ok
    ? `Enrolled — ${m.added} tokens ready.`
    : `Enrolled, but minting failed: ${(m && m.reason) || "unknown"} — use Top up.`;
}

document.getElementById("enrollBtn").addEventListener("click", async () => {
  const el = document.getElementById("onboardMsg");
  el.textContent = "Checking issuer…";
  const r = await send({ type: "start_enroll", issuer: document.getElementById("mIssuer").value.trim() });
  el.textContent = r.ok
    ? "Complete enrollment in the issuer tab, then reopen this popup."
    : "Failed: " + r.reason;
});

document.getElementById("mintBtn").addEventListener("click", async () => {
  const el = document.getElementById("mintMsg");
  const { issuers } = await send({ type: "list_issuers" });
  const rec = (issuers || []).find((r) => r.baseUrl === document.getElementById("issuerSelect").value);
  if (!rec) { el.textContent = "Select an enrolled issuer first."; return; }
  el.textContent = "Minting…";
  const r = await send({
    type: "mint", issuer: rec.baseUrl, enrollmentId: rec.enrollmentId,
    claim: document.getElementById("mClaim").value.trim(), assuranceLevel: "AAL2",
    count: Math.min(Math.max(Number(document.getElementById("mCount").value) || 1, 1), 100),
  });
  el.textContent = r.ok ? `Minted. ${r.added} new, ${r.total} total.` : "Failed: " + r.reason;
  if (r.ok) renderInventory();
});

async function renderTrust() {
  // Prefill the Trust inputs from stored settings. The popup is extension-
  // privileged, so it reads chrome.storage.local directly (the message bus is
  // for the service worker's decision logic, not for reading back saved fields).
  const { trust } = await chrome.storage.local.get({ trust: null });
  if (trust) {
    if (trust.registryUrl) document.getElementById("tUrl").value = trust.registryUrl;
    if (trust.rootKey) document.getElementById("tRoot").value = trust.rootKey;
  }
  const r = await send({ type: "refresh_registry" });
  const el = document.getElementById("trustMsg");
  if (r.ok) {
    el.textContent = r.stale
      ? `Using cached registry (${r.generatedAt}) — mirror unreachable.`
      : `Registry OK (${r.generatedAt}), ${r.issuers} approved issuer(s).`;
  } else {
    el.textContent = "No registry: " + r.reason;
  }
  return r.ok;
}

document.getElementById("trustBtn").addEventListener("click", async () => {
  const el = document.getElementById("trustMsg");
  el.textContent = "Verifying…";
  const r = await send({
    type: "set_trust",
    registryUrl: document.getElementById("tUrl").value.trim(),
    rootKey: document.getElementById("tRoot").value.trim(),
  });
  el.textContent = r.ok
    ? `Registry OK (${r.generatedAt}), ${r.issuers} approved issuer(s).`
    : "Failed: " + r.reason;
  if (r.ok) renderIssuers();
});

async function autoTopUp() {
  const { results } = await send({ type: "auto_topup" });
  const done = (results || []).filter((r) => r.ok);
  if (done.length) {
    const added = done.reduce((n, r) => n + (r.added || 0), 0);
    document.getElementById("onboardMsg").textContent = `Topped up +${added} token(s).`;
    renderInventory();
  }
  const failed = (results || []).filter((r) => !r.ok);
  if (failed.length) {
    document.getElementById("onboardMsg").textContent =
      `Top-up failed for ${failed[0].issuer}: ${failed[0].reason}`;
  }
}

// Trust-first init: verify the registry, then draw the issuer list (which is
// registry-sourced) and run the single popup-open auto-top-up.
renderTrust().then(() => { renderIssuers(); autoTopUp(); });
renderOnboardStatus();
renderInventory();
renderPending();
