// Zenithal extension — content script.
// Lightweight offline pre-screen: flags obviously risky links inline so the
// user sees a warning badge before clicking, without a network round-trip per
// link. Deep verdicts come from the backend via the context menu / popup.

(function () {
  function badge(a, r) {
    if (a.dataset.zenithal) return;
    a.dataset.zenithal = "1";
    const tag = document.createElement("span");
    const isMalicious = r.verdict === "MALICIOUS";
    tag.textContent = isMalicious ? " ⛔" : " ⚠️";
    tag.title = `Zenithal: ${r.verdict} (${r.score}/100) — ${r.threat_type || 'Potential threat'}`;
    tag.style.cssText = "font-size:11px;vertical-align:super;";
    a.appendChild(tag);
    a.style.outline = isMalicious ? "1px dashed #ef4444" : "1px dashed #f97316";
  }

  function scan() {
    const links = Array.from(document.querySelectorAll("a[href]:not([data-zenithal])"));
    if (links.length === 0) return;
    
    // Group elements by URL
    const urlsToNodes = new Map();
    links.forEach(a => {
      if (a.href.startsWith("http")) {
        if (!urlsToNodes.has(a.href)) urlsToNodes.set(a.href, []);
        urlsToNodes.get(a.href).push(a);
      } else {
        a.dataset.zenithal = "1"; // Ignore non-http links
      }
    });

    const uniqueUrls = Array.from(urlsToNodes.keys());
    if (uniqueUrls.length === 0) return;

    // Send batch scan to the background worker
    chrome.runtime.sendMessage({ type: "batch_scan", urls: uniqueUrls }, (resp) => {
      if (resp && resp.results) {
        resp.results.forEach(r => {
           const nodes = urlsToNodes.get(r.input) || [];
           if (r.verdict === "MALICIOUS" || r.verdict === "SUSPICIOUS") {
             nodes.forEach(a => badge(a, r));
           } else {
             // Mark safe so we don't scan them again
             nodes.forEach(a => a.dataset.zenithal = "1");
           }
        });
      }
    });
  }

  // Scan immediately on page load
  scan();

  // Re-scan dynamically when new links are added (e.g. infinite scrolling)
  let timeout;
  const observer = new MutationObserver(() => {
    clearTimeout(timeout);
    timeout = setTimeout(scan, 1000);
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();
