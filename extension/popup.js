// extension/popup.js
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

document.getElementById("importBtn").addEventListener("click", async () => {
  const msg = document.getElementById("importMsg");
  try {
    const parsed = JSON.parse(document.getElementById("importText").value);
    const r = await send({ type: "import_tokens", tokens: parsed.tokens || [] });
    msg.textContent = `Imported. ${r.added} new, ${r.count} total.`;
    renderInventory();
  } catch (e) {
    msg.textContent = "Invalid JSON.";
  }
});

renderInventory();
renderPending();
