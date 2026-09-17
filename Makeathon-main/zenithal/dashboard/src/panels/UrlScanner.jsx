import React, { useState } from "react";
import { Search, Globe, Server, MapPin, Cpu } from "lucide-react";
import { analyzeUrl } from "../services/api";
import { VerdictBadge, ScoreBar, ReasonList } from "../components/Shared";

const SAMPLES = [
  "http://sbi-verify-now.top/netbanking/login",
  "http://192.168.1.1/paypal/login.php",
  "https://bit.ly/3xY9kQz",
  "https://github.com",
];

export default function UrlScanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const scan = async (target) => {
    const u = target || url;
    if (!u.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      setResult(await analyzeUrl(u.trim()));
    } catch (e) {
      setError("Backend unreachable — is the API running on :8000?");
    } finally {
      setLoading(false);
    }
  };

  const intel = result?.ip_intel;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <Search className="w-7 h-7 text-cyan-400" /> URL Scanner
        </h2>
        <p className="text-slate-400 mt-1">Lexical ML + IP intelligence + IP-domain correlation, with plain-language reasons.</p>
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && scan()}
          placeholder="Paste a URL to analyze…"
          className="flex-1 bg-surface-200 border border-slate-700 rounded-lg px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
        />
        <button onClick={() => scan()} disabled={loading}
          className="px-6 py-3 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-semibold disabled:opacity-50 transition-colors">
          {loading ? "Scanning…" : "Scan URL"}
        </button>
      </div>

      <div className="flex flex-wrap gap-2">
        {SAMPLES.map((s) => (
          <button key={s} onClick={() => { setUrl(s); scan(s); }}
            className="text-xs px-3 py-1.5 rounded-full bg-surface-300 hover:bg-surface-400 text-slate-300 transition-colors">
            {s.length > 42 ? s.slice(0, 42) + "…" : s}
          </button>
        ))}
      </div>

      {error && <div className="bg-red-500/10 border border-red-500/30 text-red-300 rounded-lg p-4">{error}</div>}

      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* Verdict card */}
          <div className="lg:col-span-2 bg-surface-200 border border-slate-700/60 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <VerdictBadge verdict={result.verdict} />
              <span className="text-slate-400 text-sm">{result.threat_type}</span>
            </div>
            <div className="break-all text-slate-200 text-sm bg-surface-300/50 rounded px-3 py-2">{result.input}</div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-slate-400">Risk score</span>
                <span className="font-bold text-white">{result.score}/100</span>
              </div>
              <ScoreBar score={result.score} />
              <div className="flex gap-4 mt-2 text-xs text-slate-500">
                <span className="flex items-center gap-1"><Cpu className="w-3 h-3" /> lexical {result.lexical_score} · {result.model_used}</span>
                <span className="flex items-center gap-1"><Server className="w-3 h-3" /> IP risk +{result.ip_risk}</span>
              </div>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-2 text-sm">Why this verdict</h4>
              <ReasonList reasons={result.reasons} />
            </div>
          </div>

          {/* IP intel card */}
          <div className="bg-surface-200 border border-slate-700/60 rounded-xl p-5 space-y-3">
            <h4 className="text-white font-semibold flex items-center gap-2 text-sm">
              <Globe className="w-4 h-4 text-cyan-400" /> IP Intelligence
            </h4>
            {result.resolved_ip ? (
              <dl className="space-y-2 text-sm">
                <Row k="Resolved IP" v={result.resolved_ip} mono />
                {intel && <>
                  <Row k="Location" v={`${intel.city || "?"}, ${intel.country || "?"}`} icon={<MapPin className="w-3 h-3" />} />
                  <Row k="ASN / Org" v={intel.asn ? `AS${intel.asn} · ${intel.org}` : intel.org} />
                  <Row k="Hosting" v={intel.hosting_type} />
                  <Row k="Reputation" v={intel.reputation}
                       accent={intel.reputation === "malicious" ? "text-red-400" : intel.reputation === "suspicious" ? "text-orange-400" : "text-slate-300"} />
                  {intel.reverse_dns && <Row k="Reverse DNS" v={intel.reverse_dns} mono />}
                  <Row k="Source" v={intel.source} />
                </>}
              </dl>
            ) : (
              <p className="text-slate-500 text-sm">Domain did not resolve to an IP (dead / newly-registered / parked).</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Row({ k, v, mono, accent = "text-slate-300", icon }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-slate-500">{k}</dt>
      <dd className={`text-right ${accent} ${mono ? "font-mono text-xs" : ""} flex items-center gap-1`}>{icon}{v}</dd>
    </div>
  );
}
