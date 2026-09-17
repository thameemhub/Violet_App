import axios from "axios";

export const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
export const WS_BASE = import.meta.env.VITE_WS_URL || "ws://127.0.0.1:8000";

// Send an API key when the backend has auth enabled (set VITE_API_KEY at build).
const API_KEY = import.meta.env.VITE_API_KEY || "";
const client = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: API_KEY ? { "X-API-Key": API_KEY } : {},
});

export const analyzeUrl = (url) =>
  client.post("/api/v1/analyze/url", { url }).then((r) => r.data);

export const analyzeMessage = (text, sender) =>
  client.post("/api/v1/analyze/message", { text, sender }).then((r) => r.data);

export const analyzeLogFile = (file) => {
  const form = new FormData();
  form.append("file", file);
  return client.post("/api/v1/analyze/logfile", form).then((r) => r.data);
};

export const analyzeLogText = (text) =>
  client.post("/api/v1/analyze/logtext", { text }).then((r) => r.data);

export const getStats = () =>
  client.get("/api/v1/dashboard/stats").then((r) => r.data);

export const getDetections = (limit = 100) =>
  client.get(`/api/v1/dashboard/detections?limit=${limit}`).then((r) => r.data);

export const getAttackers = (limit = 25) =>
  client.get(`/api/v1/dashboard/attackers?limit=${limit}`).then((r) => r.data);

export const getHealth = () =>
  client.get("/api/v1/health").then((r) => r.data);
