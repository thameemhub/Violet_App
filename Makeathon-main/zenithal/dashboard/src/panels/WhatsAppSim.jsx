import React, { useState } from "react";
import { MessageSquare, Send } from "lucide-react";
import { analyzeMessage } from "../services/api";
import { VerdictBadge } from "../components/Shared";

const PRESETS = [
  "URGENT: Your SBI account is blocked. Verify now at http://sbi-verify-now.top/netbanking/login",
  "Your parcel is held. Pay ₹25 customs: http://irctc-refund-user.buzz/claim",
  "Hey, here's the doc we discussed: https://github.com/anthropics/claude-code",
];

export default function WhatsAppSim() {
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);

  const send = async (body) => {
    const b = body || text;
    if (!b.trim()) return;
    setText("");
    const mine = { from: "them", body: b, ts: new Date() };
    setMessages((m) => [...m, mine]);
    setLoading(true);
    try {
      const res = await analyzeMessage(b, "+91-99999-88888");
      setMessages((m) => [...m, { from: "guard", res, ts: new Date() }]);
    } catch {
      setMessages((m) => [...m, { from: "guard", error: true, ts: new Date() }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <MessageSquare className="w-7 h-7 text-green-400" /> WhatsApp / SMS Guard
        </h2>
        <p className="text-slate-400 mt-1">Links inside messages are auto-extracted and scanned before the user can tap them.</p>
      </div>

      <div className="flex flex-wrap gap-2">
        {PRESETS.map((p, i) => (
          <button key={i} onClick={() => send(p)}
            className="text-xs px-3 py-1.5 rounded-full bg-surface-300 hover:bg-surface-400 text-slate-300">
            {p.slice(0, 46)}…
          </button>
        ))}
      </div>

      <div className="max-w-xl mx-auto bg-[#0b141a] border border-slate-700/60 rounded-xl overflow-hidden flex flex-col" style={{ height: 460 }}>
        <div className="bg-[#1f2c34] px-4 py-3 flex items-center gap-3">
          <div className="w-9 h-9 rounded-full bg-green-600 flex items-center justify-center text-white font-bold">B</div>
          <div>
            <p className="text-white text-sm font-medium">Bank Alerts</p>
            <p className="text-slate-400 text-xs">protected by Zenithal</p>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto custom-scrollbar p-4 space-y-3">
          {messages.map((m, i) =>
            m.from === "them" ? (
              <div key={i} className="max-w-[80%] bg-[#202c33] text-slate-100 rounded-lg rounded-tl-none px-3 py-2 text-sm break-words">
                {m.body}
              </div>
            ) : (
              <div key={i} className="max-w-[90%] ml-auto">
                {m.error ? (
                  <div className="bg-red-500/10 text-red-300 rounded-lg px-3 py-2 text-sm">Scan failed — API offline.</div>
                ) : (
                  <ScanBubble res={m.res} />
                )}
              </div>
            )
          )}
          {loading && <div className="text-slate-500 text-xs">Zenithal scanning links…</div>}
        </div>

        <div className="p-3 bg-[#1f2c34] flex gap-2">
          <input value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === "Enter" && send()}
            placeholder="Type a message with a link…"
            className="flex-1 bg-[#2a3942] text-white text-sm rounded-full px-4 py-2 focus:outline-none placeholder-slate-500" />
          <button onClick={() => send()} className="w-10 h-10 rounded-full bg-green-600 hover:bg-green-500 flex items-center justify-center text-white">
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

function ScanBubble({ res }) {
  const v = res.overall_verdict;
  const border = v === "MALICIOUS" ? "border-red-500/50" : v === "SUSPICIOUS" ? "border-orange-500/50" : "border-green-500/50";
  return (
    <div className={`bg-surface-200 border ${border} rounded-lg px-3 py-2.5 space-y-2`}>
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-400">🛡️ {res.urls_found} link(s) scanned</span>
        <VerdictBadge verdict={v} />
      </div>
      {res.results.map((r, i) => (
        <div key={i} className="text-xs">
          <div className="text-slate-300 break-all">{r.input}</div>
          {r.reasons?.[0] && <div className="text-slate-500 mt-0.5">▸ {r.reasons[0]}</div>}
          {v === "MALICIOUS" && <div className="text-red-400 font-medium mt-1">⛔ Link blocked before opening.</div>}
        </div>
      ))}
    </div>
  );
}
