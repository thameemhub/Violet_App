import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from "react";
import { WS_BASE } from "../services/api";

const WebSocketContext = createContext(null);

export function WebSocketProvider({ children }) {
  const [detections, setDetections] = useState([]);
  const [attackers, setAttackers] = useState([]);
  const [connectionStatus, setConnectionStatus] = useState("disconnected");
  const wsRef = useRef(null);
  const reconnectTimeout = useRef(null);
  const reconnectDelay = useRef(1000);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    try {
      const ws = new WebSocket(`${WS_BASE}/api/v1/ws/feed`);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnectionStatus("connected");
        reconnectDelay.current = 1000;
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "detection") {
            const d = msg.data;
            setDetections((prev) => [d, ...prev].slice(0, 200));
            // maintain a lightweight attacker roll-up when an IP is present
            if (d.src_ip && d.src_ip !== "" && d.channel === "log") {
              setAttackers((prev) => {
                const others = prev.filter((a) => a.ip !== d.src_ip);
                return [
                  { ip: d.src_ip, country: d.country, lat: d.lat, lon: d.lon, risk_score: d.score },
                  ...others,
                ].slice(0, 50);
              });
            }
          }
        } catch {}
      };

      ws.onclose = () => {
        setConnectionStatus("disconnected");
        reconnectTimeout.current = setTimeout(() => {
          reconnectDelay.current = Math.min(reconnectDelay.current * 2, 15000);
          connect();
        }, reconnectDelay.current);
      };

      ws.onerror = () => ws.close();
    } catch {
      setConnectionStatus("disconnected");
    }
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current);
    };
  }, [connect]);

  return (
    <WebSocketContext.Provider value={{ detections, attackers, connectionStatus }}>
      {children}
    </WebSocketContext.Provider>
  );
}

export const useWebSocket = () => useContext(WebSocketContext);
