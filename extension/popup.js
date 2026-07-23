// extension/popup.js
import { tokensFromParsed } from "./core/protocol.js";

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
    small.textContent = "none — import some below";
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
  if (!res || !res.pending) { el.innerHTML = ""; return; }
  const c = res.consent;
  el.innerHTML = `<div class="card consent">
    <strong>${c.site}</strong> requests proof of <strong>${c.claim}</strong>
    (min assurance ${c.assurance}).
    <div class="recv">Will receive:<ul>${c.willReceive.map((x) => `<li>${x}</li>`).join("")}</ul></div>
    <div class="norecv">Will NOT receive:<ul>${c.willNotReceive.map((x) => `<li>${x}</li>`).join("")}</ul></div>
    <button id="allowBtn">Allow once</button><div id="allowMsg"></div></div>`;
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

document.getElementById("mintBtn").addEventListener("click", async () => {
  const el = document.getElementById("mintMsg");
  el.textContent = "Minting…";
  const r = await send({
    type: "mint",
    issuer: document.getElementById("mIssuer").value.trim(),
    enrollmentId: document.getElementById("mEnroll").value.trim(),
    claim: document.getElementById("mClaim").value.trim(),
    assuranceLevel: "AAL2",
    epoch: document.getElementById("mCount").dataset.epoch || "2026-Q3",
    count: Number(document.getElementById("mCount").value) || 1,
  });
  el.textContent = r.ok ? `Minted. ${r.added} new, ${r.total} total.` : "Failed: " + r.reason;
  if (r.ok) renderInventory();
});

renderInventory();
renderPending();
