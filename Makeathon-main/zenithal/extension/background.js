// Zenithal extension — background service worker.
// Adds a right-click "Scan link with Zenithal" action and notifies the verdict.

const API = "http://127.0.0.1:8000/api/v1/analyze/url";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "zenithal-scan-link",
    title: "Scan link with Zenithal",
    contexts: ["link"],
  });
  chrome.contextMenus.create({
    id: "zenithal-scan-page",
    title: "Scan this page's URL with Zenithal",
    contexts: ["page"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const url = info.menuItemId === "zenithal-scan-link" ? info.linkUrl : (info.pageUrl || tab?.url);
  if (!url) return;
  const result = await scan(url);
  notify(url, result);
});

async function scan(url) {
  try {
    const res = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    return await res.json();
  } catch {
    return { verdict: "ERROR", reasons: ["Zenithal backend unreachable on :8000"] };
  }
}

function notify(url, r) {
  const emoji = r.verdict === "MALICIOUS" ? "⛔" : r.verdict === "SUSPICIOUS" ? "⚠️" : r.verdict === "SAFE" ? "✅" : "❓";
  chrome.notifications.create({
    type: "basic",
    iconUrl: iconDataUrl(r.verdict),
    title: `${emoji} ${r.verdict} ${r.score != null ? "(" + r.score + "/100)" : ""}`,
    message: (r.reasons && r.reasons[0]) || url,
  });
}

// Minimal coloured square icon so notifications render without image assets.
function iconDataUrl(verdict) {
  const color = verdict === "MALICIOUS" ? "%23ef4444" : verdict === "SUSPICIOUS" ? "%23f97316" : "%2322c55e";
  return `data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' width='64' height='64'><rect width='64' height='64' rx='12' fill='${color}'/></svg>`;
}

// Allow the popup to request scans.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "scan") {
    scan(msg.url).then(sendResponse);
    return true; // async
  }
  if (msg.type === "batch_scan") {
    batchScan(msg.urls).then(sendResponse);
    return true; // async
  }
});

async function batchScan(urls) {
  try {
    const res = await fetch("http://127.0.0.1:8000/api/v1/analyze/urls", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls }),
    });
    return await res.json();
  } catch {
    return { results: [] };
  }
}
