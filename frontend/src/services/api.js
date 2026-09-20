import axios from "axios";

const API_BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

const client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 20000,
});

export const api = {
  getDashboard: () => client.get("/api/dashboard").then((r) => r.data),
  getResources: (type) =>
    client.get("/api/resources", { params: type ? { type } : {} }).then((r) => r.data),
  getVulnerabilities: (filters = {}) =>
    client.get("/api/vulnerabilities", { params: filters }).then((r) => r.data),
  getAttackGraph: () => client.get("/api/attack-graph").then((r) => r.data),
  getRemediation: () => client.get("/api/remediation").then((r) => r.data),
  triggerScan: (payload) => client.post("/api/scan", payload).then((r) => r.data),
  health: () => client.get("/api/health").then((r) => r.data),
};

export default api;
