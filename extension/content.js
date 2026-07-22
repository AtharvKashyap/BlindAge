// extension/content.js
// Bridge between the page (window.postMessage) and the extension (chrome.runtime).
window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const d = event.data || {};
  if (d.source === "blindage-page" && d.kind === "request" && d.challenge) {
    chrome.runtime.sendMessage(
      { type: "page_request", challenge: d.challenge, pageHost: location.hostname },
      () => void chrome.runtime.lastError // ignore if no receiver
    );
  }
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "deliver_presentation") {
    window.postMessage(
      { source: "blindage-ext", kind: "presentation", presentation: msg.presentation },
      location.origin
    );
  }
});
