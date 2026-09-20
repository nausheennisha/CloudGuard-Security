import React, { useCallback, useEffect, useState } from "react";
import api from "./services/api";
import Dashboard from "./components/Dashboard";
import AttackPathGraph from "./components/AttackPathGraph";
import VulnerabilityTable from "./components/VulnerabilityTable";
import RemediationPanel from "./components/RemediationPanel";

const TABS = [
  { id: "dashboard", label: "Dashboard" },
  { id: "graph", label: "Attack Graph" },
  { id: "vulnerabilities", label: "Vulnerabilities" },
  { id: "remediation", label: "Remediation" },
];

export default function App() {
  const [tab, setTab] = useState("dashboard");
  const [summary, setSummary] = useState(null);
  const [graphData, setGraphData] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [remediationPlan, setRemediationPlan] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [dash, graph, vulns, remediation] = await Promise.all([
        api.getDashboard(),
        api.getAttackGraph(),
        api.getVulnerabilities(),
        api.getRemediation(),
      ]);
      setSummary(dash);
      setGraphData(graph);
      setVulnerabilities(vulns.vulnerabilities);
      setRemediationPlan(remediation.remediation_plan);
    } catch (err) {
      setError(
        "Could not reach the CloudGuard API. Make sure the backend is running at " +
          (process.env.REACT_APP_API_URL || "http://localhost:8000") + "."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  const handleScan = async () => {
    setScanning(true);
    try {
      await api.triggerScan({ regions: ["us-east-1"], use_live_aws: false });
      await loadAll();
    } catch (err) {
      setError("Scan failed. See console for details.");
      // eslint-disable-next-line no-console
      console.error(err);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-cg-bg">
      <header className="border-b border-cg-border bg-cg-panel/60 backdrop-blur sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-md bg-cg-accent/15 border border-cg-accent/30 flex items-center justify-center text-cg-accent font-mono font-bold">
              ⛊
            </div>
            <div>
              <h1 className="font-mono text-lg font-semibold text-slate-100 leading-tight">
                CloudGuard
              </h1>
              <p className="text-xs text-slate-500 leading-tight">
                Cloud security analysis &amp; attack path visualization
              </p>
            </div>
          </div>
          <button
            onClick={handleScan}
            disabled={scanning}
            className="bg-cg-accent text-cg-bg font-medium text-sm px-4 py-2 rounded-md hover:brightness-110 disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
            {scanning ? "Scanning…" : "Run scan"}
          </button>
        </div>
        <nav className="max-w-7xl mx-auto px-6 flex gap-1">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-4 py-2.5 text-sm border-b-2 transition-colors ${
                tab === t.id
                  ? "border-cg-accent text-slate-100"
                  : "border-transparent text-slate-500 hover:text-slate-300"
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-6">
        {error && (
          <div className="mb-4 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3">
            {error}
          </div>
        )}

        {tab === "dashboard" && <Dashboard summary={summary} loading={loading} />}
        {tab === "graph" && <AttackPathGraph graphData={graphData} loading={loading} />}
        {tab === "vulnerabilities" && (
          <VulnerabilityTable vulnerabilities={vulnerabilities} loading={loading} />
        )}
        {tab === "remediation" && (
          <RemediationPanel plan={remediationPlan} loading={loading} />
        )}
      </main>
    </div>
  );
}
