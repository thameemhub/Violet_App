import React from "react";
import { AlertTriangle, ShieldAlert, ShieldCheck } from "lucide-react";

export const VERDICT_STYLE = {
  MALICIOUS: { color: "#ef4444", bg: "bg-red-500/10", text: "text-red-400", ring: "ring-red-500/40", Icon: ShieldAlert },
  SUSPICIOUS: { color: "#f97316", bg: "bg-orange-500/10", text: "text-orange-400", ring: "ring-orange-500/40", Icon: AlertTriangle },
  SAFE: { color: "#22c55e", bg: "bg-green-500/10", text: "text-green-400", ring: "ring-green-500/40", Icon: ShieldCheck },
};

export function VerdictBadge({ verdict }) {
  const s = VERDICT_STYLE[verdict] || VERDICT_STYLE.SAFE;
  const { Icon } = s;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${s.bg} ${s.text} ring-1 ${s.ring}`}>
      <Icon className="w-3.5 h-3.5" />
      {verdict}
    </span>
  );
}

export function ScoreBar({ score }) {
  const color = score >= 70 ? "#ef4444" : score >= 40 ? "#f97316" : "#22c55e";
  return (
    <div className="w-full h-2 rounded-full bg-surface-300 overflow-hidden">
      <div className="h-full rounded-full transition-all duration-500" style={{ width: `${score}%`, background: color }} />
    </div>
  );
}

export function StatTile({ label, value, sub, accent = "text-cyan-400" }) {
  return (
    <div className="bg-surface-200 border border-slate-700/60 rounded-xl p-4">
      <p className="text-slate-400 text-xs uppercase tracking-wider">{label}</p>
      <p className={`text-3xl font-bold mt-1 ${accent}`}>{value}</p>
      {sub && <p className="text-slate-500 text-xs mt-1">{sub}</p>}
    </div>
  );
}

export function ReasonList({ reasons }) {
  if (!reasons?.length) return null;
  return (
    <ul className="space-y-2">
      {reasons.map((r, i) => (
        <li key={i} className="flex gap-2 text-sm text-slate-300">
          <span className="text-cyan-400 mt-0.5">▸</span>
          <span dangerouslySetInnerHTML={{ __html: escapeButCode(r) }} />
        </li>
      ))}
    </ul>
  );
}

// Render `code` spans from backtick-wrapped evidence, escape everything else.
function escapeButCode(s) {
  const esc = (t) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return esc(s).replace(/`([^`]+)`/g, '<code class="px-1 py-0.5 rounded bg-slate-800 text-cyan-300 text-xs">$1</code>');
}
