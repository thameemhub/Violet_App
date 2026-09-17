import React, { useEffect, useState } from "react";
import { Activity } from "lucide-react";
import { useWebSocket } from "../context/WebSocketContext";
import { getDetections } from "../services/api";
import { VerdictBadge } from "../components/Shared";

const CHANNEL_LABEL = { url: "URL", log: "Server Log", message: "WhatsApp/SMS" };

export default function ThreatFeed() {
  const { detections: live } = useWebSocket();
  const [seed, setSeed] = useState([]);

  useEffect(() => {
    getDetections(100).then((d) => setSeed(d.detections || [])).catch(() => {});
  }, []);

  // Merge live (prepended) with seeded history, dedupe by id.
  const seen = new Set();
  const all = [...live, ...seed].filter((d) => {
    const key = d.id ?? `${d.input}-${d.created_at}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <Activity className="w-7 h-7 text-cyan-400" /> Live Threat Feed
        </h2>
        <p className="text-slate-400 mt-1">Every scored event across URLs, server logs and messages, streamed in real time.</p>
      </div>

      <div className="bg-surface-200 border border-slate-700/60 rounded-xl overflow-hidden">
        <div className="divide-y divide-slate-800 max-h-[70vh] overflow-y-auto custom-scrollbar">
          {all.length === 0 && (
            <div className="p-10 text-center text-slate-500">
              No detections yet. Scan a URL or upload a log to populate the feed.
            </div>
          )}
          {all.map((d, i) => (
            <div key={d.id ?? i} className="px-4 py-3 hover:bg-surface-300/40 threat-card-enter">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <VerdictBadge verdict={d.verdict} />
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-700 text-slate-300">{CHANNEL_LABEL[d.channel] || d.channel}</span>
                  {d.country && <span className="text-xs text-slate-500">{d.country}</span>}
                </div>
                <span className="text-xs text-slate-500 shrink-0">{fmt(d.created_at)}</span>
              </div>
              <div className="text-sm text-slate-300 mt-1 break-all">{d.input}</div>
              {d.reasons?.[0] && <div className="text-xs text-slate-500 mt-1">▸ {d.reasons[0]}</div>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function fmt(ts) {
  if (!ts) return "";
  try { return new Date(ts).toLocaleTimeString(); } catch { return ""; }
}
