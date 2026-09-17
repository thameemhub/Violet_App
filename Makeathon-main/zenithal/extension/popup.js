// Zenithal extension — popup logic.

const input = document.getElementById("url");
const out = document.getElementById("out");

// Pre-fill with the active tab's URL.
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs[0]?.url) input.value = tabs[0].url;
});

document.getElementById("scan").addEventListener("click", run);
input.addEventListener("keydown", (e) => e.key === "Enter" && run());

function run() {
  const url = input.value.trim();
  if (!url) return;
  out.innerHTML = '<div class="verdict ERROR">Scanning…</div>';
  chrome.runtime.sendMessage({ type: "scan", url }, (r) => {
    if (!r) { out.innerHTML = '<div class="verdict ERROR">No response.</div>'; return; }
    const reasons = (r.reasons || []).slice(0, 4).map((x) => `<li>${escapeHtml(x)}</li>`).join("");
    out.innerHTML = `
      <div class="verdict ${r.verdict}">
        <div><b>${r.verdict}</b> ${r.score != null ? `<span class="score">${r.score}/100</span>` : ""}</div>
        ${r.threat_type ? `<div style="font-size:11px;opacity:.8">${escapeHtml(r.threat_type)}</div>` : ""}
        <ul class="reasons">${reasons}</ul>
      </div>`;
  });
}

function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
