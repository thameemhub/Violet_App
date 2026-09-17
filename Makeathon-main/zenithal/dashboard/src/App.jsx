import React, { useEffect, useState } from "react";
import { Shield, Activity, Search, FileText, Map as MapIcon, MessageSquare } from "lucide-react";
import { WebSocketProvider, useWebSocket } from "./context/WebSocketContext";
import { getStats, getHealth } from "./services/api";
import ThreatFeed from "./panels/ThreatFeed";
import UrlScanner from "./panels/UrlScanner";
import LogAnalyzer from "./panels/LogAnalyzer";
import AttackerMap from "./panels/AttackerMap";
import WhatsAppSim from "./panels/WhatsAppSim";

const NAV = [
  { id: "feed", label: "Threat Feed", icon: Activity, C: ThreatFeed },
  { id: "url", label: "URL Scanner", icon: Search, C: UrlScanner },
  { id: "logs", label: "Log Analyzer", icon: FileText, C: LogAnalyzer },
  { id: "map", label: "Attacker Map", icon: MapIcon, C: AttackerMap },
  { id: "chat", label: "WhatsApp Guard", icon: MessageSquare, C: WhatsAppSim },
];

function Shell() {
  const [active, setActive] = useState("feed");
  const [open, setOpen] = useState(false);
  const { connectionStatus, detections } = useWebSocket();
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState(null);

  useEffect(() => {
    const load = () => getStats().then(setStats).catch(() => {});
    load();
    getHealth().then(setHealth).catch(() => {});
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, []);
  // refresh stats whenever new detections arrive
  useEffect(() => { getStats().then(setStats).catch(() => {}); }, [detections.length]);

  const Active = NAV.find((n) => n.id === active)?.C || ThreatFeed;

  return (
    <div className="flex flex-col md:flex-row h-screen bg-[#0b1120] overflow-hidden">
      {/* Mobile header */}
      <div className="md:hidden flex items-center justify-between p-4 border-b border-surface-300 bg-surface-100">
        <Brand />
        <button onClick={() => setOpen(!open)} className="p-2 text-slate-300">☰</button>
      </div>

      {/* Sidebar */}
      <aside className={`fixed md:relative z-40 w-64 h-full bg-surface-100 border-r border-surface-300 flex flex-col transition-transform ${open ? "translate-x-0" : "-translate-x-full md:translate-x-0"}`}>
        <div className="hidden md:block p-5 border-b border-surface-300"><Brand /></div>
        <div className="px-5 py-3 border-b border-surface-300">
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${connectionStatus === "connected" ? "bg-green-400 pulse-dot" : "bg-red-500"}`} />
            <span className="text-xs text-slate-400 uppercase tracking-wider">{connectionStatus === "connected" ? "Live" : "Reconnecting"}</span>
          </div>
          {health && (
            <p className="text-[10px] text-slate-500 mt-2 leading-relaxed">
              URL model: {health.url_model}<br />
              Payload: {health.payload_model}<br />
              Geo: {health.geo_backend}
            </p>
          )}
        </div>
        <nav className="flex-1 py-4 overflow-y-auto custom-scrollbar">
          {NAV.map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => { setActive(id); setOpen(false); }}
              className={`w-full flex items-center gap-3 px-5 py-3 text-sm transition-all ${active === id ? "bg-cyan-500/10 text-cyan-400 border-r-2 border-cyan-400 font-semibold" : "text-slate-400 hover:bg-surface-200 hover:text-white"}`}>
              <Icon className="w-4 h-4" /> {label}
            </button>
          ))}
        </nav>
        <div className="p-4 border-t border-surface-300 text-[10px] text-slate-500">
          SIH25229 · The Zenithal
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto bg-[#0b1120] custom-scrollbar">
        <StatsBar stats={stats} />
        <div className="p-4 md:p-6"><Active /></div>
      </main>
    </div>
  );
}

function Brand() {
  return (
    <div className="flex items-center gap-3">
      <Shield className="w-7 h-7 text-cyan-400" />
      <div>
        <h1 className="text-lg font-bold text-white leading-tight">Zenithal</h1>
        <span className="text-[10px] text-slate-400 uppercase tracking-wider">URL Threat Intel · IP Data</span>
      </div>
    </div>
  );
}

function StatsBar({ stats }) {
  if (!stats) return null;
  const items = [
    { label: "Detections", value: stats.total_detections, c: "text-slate-200" },
    { label: "Malicious", value: stats.malicious, c: "text-red-400" },
    { label: "Suspicious", value: stats.suspicious, c: "text-orange-400" },
    { label: "Attacker IPs", value: stats.unique_attackers, c: "text-cyan-400" },
    { label: "Countries", value: stats.countries, c: "text-purple-400" },
  ];
  return (
    <div className="grid grid-cols-2 sm:grid-cols-5 gap-px bg-slate-800 border-b border-slate-800">
      {items.map((it) => (
        <div key={it.label} className="bg-[#0b1120] px-4 py-3">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider">{it.label}</p>
          <p className={`text-xl font-bold ${it.c}`}>{it.value ?? 0}</p>
        </div>
      ))}
    </div>
  );
}

export default function App() {
  return (
    <WebSocketProvider>
      <Shell />
    </WebSocketProvider>
  );
}
