import React, { useState } from "react";
import { Upload, FileText, ShieldAlert } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { analyzeLogFile, analyzeLogText } from "../services/api";
import { VerdictBadge, StatTile, ReasonList } from "../components/Shared";

const TYPE_COLORS = {
  SQLi: "#ef4444", XSS: "#f97316", Traversal: "#eab308",
  CmdInjection: "#a855f7", LFI_RFI: "#06b6d4",
};

export default function LogAnalyzer() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);

  const onFile = async (file) => {
    if (!file) return;
    setLoading(true); setError(null); setReport(null); setSelected(null);
    try {
      setReport(await analyzeLogFile(file));
    } catch {
      setError("Analysis failed — is the API running on :8000?");
    } finally {
      setLoading(false);
    }
  };

  const chartData = report
    ? Object.entries(report.attack_breakdown).map(([type, count]) => ({ type, count }))
    : [];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <FileText className="w-7 h-7 text-cyan-400" /> Server Log / Attack Analyzer
        </h2>
        <p className="text-slate-400 mt-1">
          Upload a web-server access log. Zenithal identifies URL-based attacks
          (SQLi / XSS / traversal / command-injection / LFI) and ranks the attacker IPs.
        </p>
      </div>

      {/* Dropzone */}
      <label className="block cursor-pointer">
        <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-xl p-8 text-center transition-colors bg-surface-200/50">
          <Upload className="w-8 h-8 mx-auto text-slate-500 mb-2" />
          <p className="text-slate-300 font-medium">Drop an access log or click to upload</p>
          <p className="text-slate-500 text-sm mt-1">Apache/Nginx common format · try <code className="text-cyan-300">demo/sample_access.log</code></p>
          <input type="file" className="hidden" accept=".log,.txt,text/plain"
                 onChange={(e) => onFile(e.target.files?.[0])} />
        </div>
      </label>

      {loading && <p className="text-cyan-400 text-sm">Analyzing log…</p>}
      {error && <div className="bg-red-500/10 border border-red-500/30 text-red-300 rounded-lg p-4">{error}</div>}

      {report && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatTile label="Requests" value={report.total_requests} accent="text-slate-200" />
            <StatTile label="Attacks Found" value={report.malicious_requests} accent="text-red-400" />
            <StatTile label="Unique Attackers" value={report.unique_attackers} accent="text-orange-400" />
            <StatTile label="Techniques" value={Object.keys(report.attack_breakdown).length} accent="text-cyan-400" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* Attack breakdown chart */}
            <div className="bg-surface-200 border border-slate-700/60 rounded-xl p-5">
              <h4 className="text-white font-semibold mb-4 text-sm">Attack-type breakdown</h4>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={chartData} margin={{ left: -20 }}>
                  <XAxis dataKey="type" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8 }} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {chartData.map((d) => <Cell key={d.type} fill={TYPE_COLORS[d.type] || "#3b82f6"} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Attacker leaderboard */}
            <div className="bg-surface-200 border border-slate-700/60 rounded-xl p-5">
              <h4 className="text-white font-semibold mb-3 text-sm flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-400" /> Top Attacker IPs
              </h4>
              <div className="space-y-2 max-h-[220px] overflow-y-auto custom-scrollbar pr-1">
                {report.attackers.map((a) => (
                  <button key={a.ip} onClick={() => setSelected(a)}
                    className={`w-full text-left px-3 py-2 rounded-lg transition-colors ${selected?.ip === a.ip ? "bg-cyan-500/10 ring-1 ring-cyan-500/40" : "bg-surface-300/50 hover:bg-surface-300"}`}>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-sm text-slate-200">{a.ip}</span>
                      <span className={`text-sm font-bold ${a.risk_score >= 70 ? "text-red-400" : "text-orange-400"}`}>{a.risk_score}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs text-slate-500 mt-0.5">
                      <span>{a.intel?.country} · {a.intel?.hosting_type}</span>
                      <span>{a.total_hits} hits</span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Selected attacker detail */}
          {selected && (
            <div className="bg-surface-200 border border-slate-700/60 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-white font-semibold font-mono">{selected.ip}</h4>
                <VerdictBadge verdict={selected.risk_score >= 70 ? "MALICIOUS" : "SUSPICIOUS"} />
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
                <Meta k="Country" v={selected.intel?.country} />
                <Meta k="ASN / Org" v={selected.intel?.asn ? `AS${selected.intel.asn}` : selected.intel?.org} />
                <Meta k="Hosting" v={selected.intel?.hosting_type} />
                <Meta k="Reputation" v={selected.intel?.reputation} />
              </div>
              <ReasonList reasons={selected.reasons} />
            </div>
          )}

          {/* Raw detections */}
          <div className="bg-surface-200 border border-slate-700/60 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-slate-700"><h4 className="text-white font-semibold text-sm">Malicious requests ({report.detections.length})</h4></div>
            <div className="divide-y divide-slate-800 max-h-[320px] overflow-y-auto custom-scrollbar">
              {report.detections.map((d, i) => (
                <div key={i} className="px-4 py-2.5 hover:bg-surface-300/40">
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-mono text-xs text-slate-400">{d.src_ip}</span>
                    <span className="text-xs font-semibold px-2 py-0.5 rounded" style={{ color: TYPE_COLORS[d.attack_type], background: (TYPE_COLORS[d.attack_type] || "#3b82f6") + "1a" }}>{d.label}</span>
                  </div>
                  <div className="font-mono text-xs text-slate-300 mt-1 break-all">{d.method} {d.target}</div>
                  {d.evidence?.[0] && <div className="text-xs text-slate-500 mt-0.5" dangerouslySetInnerHTML={{ __html: codeHtml(d.evidence[0]) }} />}
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function Meta({ k, v }) {
  return (
    <div className="bg-surface-300/50 rounded-lg px-3 py-2">
      <p className="text-slate-500 text-xs">{k}</p>
      <p className="text-slate-200 truncate">{v || "—"}</p>
    </div>
  );
}
function codeHtml(s) {
  const esc = s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return esc.replace(/`([^`]+)`/g, '<code class="text-cyan-300">$1</code>');
}
