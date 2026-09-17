import React, { useEffect, useState } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup, ZoomControl } from "react-leaflet";
import { Map as MapIcon } from "lucide-react";
import { useWebSocket } from "../context/WebSocketContext";
import { getDetections } from "../services/api";
import { StatTile } from "../components/Shared";

const COLOR = { MALICIOUS: "#ef4444", SUSPICIOUS: "#f97316", SAFE: "#22c55e" };

export default function AttackerMap() {
  const { detections: live } = useWebSocket();
  const [seed, setSeed] = useState([]);

  useEffect(() => {
    getDetections(150).then((d) => setSeed(d.detections || [])).catch(() => {});
  }, []);

  // Only plot events that carry real coordinates from IP intelligence.
  const seen = new Set();
  const points = [...live, ...seed]
    .filter((d) => (d.lat || d.lon) && !(d.lat === 0 && d.lon === 0))
    .filter((d) => {
      const key = d.id ?? `${d.src_ip}-${d.created_at}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

  const countries = new Set(points.map((p) => p.country).filter(Boolean));
  const malicious = points.filter((p) => p.verdict === "MALICIOUS").length;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <MapIcon className="w-7 h-7 text-cyan-400" /> Attacker Geo-Map
        </h2>
        <p className="text-slate-400 mt-1">Every pin is geolocated from real IP intelligence (GeoLite2 / ASN reference).</p>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <StatTile label="Plotted Events" value={points.length} accent="text-cyan-400" />
        <StatTile label="Countries" value={countries.size} accent="text-purple-400" />
        <StatTile label="Malicious" value={malicious} accent="text-red-400" />
      </div>

      <div className="bg-surface-200 border border-slate-700/60 rounded-xl overflow-hidden" style={{ height: 520 }}>
        <MapContainer center={[25, 20]} zoom={2} style={{ height: "100%", width: "100%" }} zoomControl={false} worldCopyJump>
          <TileLayer
            attribution='&copy; CARTO'
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          />
          <ZoomControl position="bottomright" />
          {points.map((p, i) => {
            const c = COLOR[p.verdict] || "#22c55e";
            return (
              <CircleMarker key={p.id ?? i} center={[p.lat, p.lon]}
                radius={p.verdict === "MALICIOUS" ? 9 : 6}
                pathOptions={{ color: c, fillColor: c, fillOpacity: 0.55, weight: 2 }}>
                <Popup>
                  <div style={{ fontSize: 13 }}>
                    <strong>{p.src_ip || p.input}</strong><br />
                    {p.country}<br />
                    {p.verdict} · {Math.round(p.score)}<br />
                    {p.threat_type}
                  </div>
                </Popup>
              </CircleMarker>
            );
          })}
        </MapContainer>
      </div>

      {points.length === 0 && (
        <p className="text-slate-500 text-sm text-center">
          No geolocated events yet. Upload <code className="text-cyan-300">demo/sample_access.log</code> to light up the map.
        </p>
      )}
    </div>
  );
}
