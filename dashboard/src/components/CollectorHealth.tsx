import { useEffect, useState } from "react";
import "./CollectorHealth.css";

const API = import.meta.env.DEV ? "http://127.0.0.1:8001" : "";

type Collector = {
  collector: string;
  label: string;
  status: "active" | "degraded" | "stale" | "stopped" | "not_connected";
  age_seconds: number | null;
  last_seen_utc: string | null;
  detail: string | null;
};

type HealthResponse = {
  backend: string;
  database: string;
  collectors: Collector[];
};

function statusText(status: Collector["status"]): string {
  return {
    active: "Heartbeat active",
    degraded: "Degraded",
    stale: "Heartbeat lost",
    stopped: "Stopped",
    not_connected: "Not monitored yet",
  }[status];
}

export default function CollectorHealth() {
  const [data, setData] = useState<HealthResponse | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let mounted = true;

    async function refresh() {
      try {
        const response = await fetch(`${API}/collectors/status`, {
          cache: "no-store",
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const next: HealthResponse = await response.json();

        if (mounted) {
          setData(next);
          setError("");
        }
      } catch (err) {
        if (mounted) {
          setData(null);
          setError(err instanceof Error ? err.message : "Connection failed");
        }
      }
    }

    void refresh();

    const timer = window.setInterval(() => void refresh(), 5000);

    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <section className="panel collector-health" id="collector-health">
      <div className="panel-header">
        <div>
          <h2>Collector Health</h2>
          <p>Live collector heartbeats · Refreshes every 5 seconds</p>
        </div>
      </div>

      {error && <p className="ch-error">Backend unavailable: {error}</p>}

      <div className="ch-grid" aria-live="polite">
        <div className="ch-item">
          <strong>Backend API</strong>
          <span className={`ch-status ${data ? "ch-active" : "ch-stale"}`}>
            {data ? "Online" : "Offline / unreachable"}
          </span>
        </div>

        <div className="ch-item">
          <strong>SQLite database</strong>
          <span className={`ch-status ${data ? "ch-active" : "ch-stale"}`}>
            {data ? "Connected" : "Unknown"}
          </span>
        </div>

        {data?.collectors.map((collector) => (
          <div className="ch-item" key={collector.collector}>
            <strong>{collector.label}</strong>

            <span className={`ch-status ch-${collector.status}`}>
              {statusText(collector.status)}
            </span>

            {collector.age_seconds !== null && (
              <small>Last heartbeat: {collector.age_seconds}s ago</small>
            )}

            {collector.detail && <small>{collector.detail}</small>}
          </div>
        ))}
      </div>

      <p className="ch-note">
        Heartbeats confirm the collector is reporting. They do not by themselves
        prove that packets or Windows audit records were captured.
      </p>
    </section>
  );
}
