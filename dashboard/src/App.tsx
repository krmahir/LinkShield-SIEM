import { useCallback, useEffect, useMemo, useState } from "react";
import LiveTraffic from "./components/LiveTraffic";
import TrafficMap from ".//TrafficMap";
import BandwidthTimeline from "./components/BandwidthTimeline";
import UnifiedEventExplorer from "./components/UnifiedEventExplorer";
import {
  Activity,
  ArrowDownRight,
  ArrowRight,
  Bell,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Database,
  LayoutDashboard,
  Network,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import "./App.css";

const API = "http://127.0.0.1:8001";

type Severity = "info" | "low" | "medium" | "high" | "critical";

interface SecurityEvent {
  id: number;
  hostname: string;
  event_type: string;
  description: string;
  local_ip?: string | null;
  local_port?: number | null;
  remote_ip?: string | null;
  remote_port?: number | null;
  process_name?: string | null;
  process_id?: number | null;
  severity: Severity;
  timestamp: string;
  received_at: string;
}

interface DetectionAlert {
  id: number;
  event_id: number;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  created_at: string;
  hostname: string;
  remote_ip: string | null;
  remote_port: number | null;
  process_name: string | null;
}

interface Stats {
  total_events: number;
  events_last_24_hours: number;
  by_severity: Record<Severity, number>;
  top_hosts: { hostname: string; count: number }[];
  by_event_type: { event_type: string; count: number }[];
  total_alerts: number;
}

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

function formatTime(value: string) {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return value;

  return date.toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function App() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [alerts, setAlerts] = useState<DetectionAlert[]>([]);

  const refresh = useCallback(async () => {
    try {
      const [statsResponse, eventsResponse, alertsResponse] = await Promise.all(
        [
          fetch(`${API}/stats`),
          fetch(`${API}/events?limit=100`),
          fetch(`${API}/alerts?limit=100`),
        ],
      );

      if (!statsResponse.ok || !eventsResponse.ok || !alertsResponse.ok) {
        throw new Error("The SIEM API returned an error.");
      }

      const nextStats: Stats = await statsResponse.json();

      const nextEvents: SecurityEvent[] = await eventsResponse.json();

      const nextAlerts: DetectionAlert[] = await alertsResponse.json();

      setStats(nextStats);
      setEvents(nextEvents);
      setAlerts(nextAlerts);

      setLastUpdated(new Date());
      setError("");
    } catch (error) {
      console.error("Failed to refresh SIEM data:", error);

      setError(
        "Cannot retrieve SIEM data. Check that FastAPI is running and the /stats, /events and /alerts endpoints are working.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();

    const timer = window.setInterval(() => {
      void refresh();
    }, 5000);

    return () => window.clearInterval(timer);
  }, [refresh]);

  const filteredEvents = useMemo(() => {
    const query = search.toLowerCase().trim();

    return events.filter((event) => {
      const matchesSeverity = severity === "all" || event.severity === severity;

      const searchableText = [
        event.hostname,
        event.event_type,
        event.description,
        event.remote_ip ?? "",
        event.local_ip ?? "",
        event.process_name ?? "",
      ]
        .join(" ")
        .toLowerCase();

      return matchesSeverity && (!query || searchableText.includes(query));
    });
  }, [events, search, severity]);

  const severityCounts = stats?.by_severity;

  const maximumSeverity = Math.max(
    1,
    ...severityOrder.map((level) => severityCounts?.[level] ?? 0),
  );

  const maximumHostCount = Math.max(
    1,
    ...(stats?.top_hosts.map((host) => host.count) ?? []),
  );

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#overview">
          <div className="brand-mark">
            <ShieldCheck size={23} />
          </div>
          <div>
            <strong>LinkShield</strong>
            <span>SECURITY OPERATIONS</span>
          </div>
        </a>

        <div className="nav-label">MONITORING</div>

        <nav className="side-nav">
          <a className="nav-item active" href="#overview">
            <LayoutDashboard size={18} />
            Overview
            <ChevronRight size={15} className="nav-chevron" />
          </a>
          <a className="nav-item" href="#events">
            <Activity size={18} />
            Event explorer
          </a>
          <a className="nav-item" href="#alerts">
            <ShieldAlert size={18} />
            Security alerts
          </a>
          <a className="nav-item" href="#hosts">
            <Server size={18} />
            Hosts
          </a>
          <a className="nav-item" href="#events">
            <Network size={18} />
            Network activity
          </a>
        </nav>

        <div className="sidebar-bottom">
          <div className="sensor-card">
            <div className="sensor-icon">
              <CheckCircle2 size={18} />
            </div>
            <div className="sensor-copy">
              <strong>Local sensor</strong>
              <span>Windows agent</span>
            </div>
            <span className="live-dot" />
          </div>

          <div className="sidebar-footer">
            <Database size={14} />
            <span>LinkShield SIEM</span>
            <span>v0.2.0</span>
          </div>
        </div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar">
          <div>
            <div className="eyebrow">SECURITY OPERATIONS / OVERVIEW</div>
            <h1>Security overview</h1>
            <p className="page-subtitle">
              Monitor network activity and security events across your
              environment.
            </p>
          </div>

          <div className="topbar-actions">
            <div className="connection-status">
              <span className={`status-dot ${error ? "offline" : ""}`} />
              {error ? "API offline" : stats ? "API connected" : "Connecting"}
            </div>

            <button
              className="refresh-button"
              onClick={() => void refresh()}
              disabled={loading}
            >
              <RefreshCw size={15} className={loading ? "spinning" : ""} />
              Refresh
            </button>
          </div>
        </header>

        {error && (
          <div className="error-banner">
            <ShieldAlert size={18} />
            <span>{error}</span>
          </div>
        )}
        <div className="hero-grid">
          <section className="metric-grid">
            <article className="metric-card">
              <div className="metric-top">
                <span>Total events</span>
                <div className="metric-icon blue">
                  <Activity size={19} />
                </div>
              </div>
              <div className="metric-value">
                {(stats?.total_events ?? 0).toLocaleString()}
              </div>
              <div className="metric-foot">
                <Database size={14} />
                All stored events
              </div>
            </article>

            <article className="metric-card">
              <div className="metric-top">
                <span>Last 24 hours</span>
                <div className="metric-icon cyan">
                  <Clock3 size={19} />
                </div>
              </div>
              <div className="metric-value">
                {(stats?.events_last_24_hours ?? 0).toLocaleString()}
              </div>
              <div className="metric-foot">
                <Activity size={14} />
                Events by occurrence time
              </div>
            </article>

            <article className="metric-card">
              <div className="metric-top">
                <span>Detection alerts</span>
                <div className="metric-icon red">
                  <ShieldAlert size={19} />
                </div>
              </div>
              <div className="metric-value">{stats?.total_alerts ?? 0}</div>
              <div className="metric-foot">
                <ArrowDownRight size={14} />
                Rule-generated findings
              </div>
            </article>

            <article className="metric-card">
              <div className="metric-top">
                <span>Event categories</span>
                <div className="metric-icon purple">
                  <Network size={19} />
                </div>
              </div>
              <div className="metric-value">
                {stats?.by_event_type.length ?? 0}
              </div>
              <div className="metric-foot">
                <Activity size={14} />
                Distinct event types
              </div>
            </article>
          </section>
          <TrafficMap />
        </div>

        <section className="overview-grid">
          <article className="panel" id="severity">
            <div className="panel-header">
              <div>
                <h2>Severity distribution</h2>
                <p>All stored events by assigned severity</p>
              </div>
              <ShieldCheck size={19} className="muted-icon" />
            </div>

            <div className="severity-list">
              {severityOrder.map((level) => {
                const count = severityCounts?.[level] ?? 0;
                const width = (count / maximumSeverity) * 100;

                return (
                  <div className="severity-row" key={level}>
                    <span className={`severity-dot ${level}`} />
                    <span className="severity-name">{level}</span>
                    <div className="bar-track">
                      <div
                        className={`bar-fill ${level}`}
                        style={{ width: `${width}%` }}
                      />
                    </div>
                    <span className="severity-count">{count}</span>
                  </div>
                );
              })}
            </div>
          </article>

          <article className="panel" id="hosts">
            <div className="panel-header">
              <div>
                <h2>Top reporting hosts</h2>
                <p>Devices ranked by stored event count</p>
              </div>
              <Server size={19} className="muted-icon" />
            </div>

            <div className="host-list">
              {(stats?.top_hosts ?? []).map((host) => (
                <div className="host-row" key={host.hostname}>
                  <div className="host-icon">
                    <Server size={16} />
                  </div>
                  <div className="host-info">
                    <strong>{host.hostname}</strong>
                    <div className="bar-track host-track">
                      <div
                        className="bar-fill blue"
                        style={{
                          width: `${(host.count / maximumHostCount) * 100}%`,
                        }}
                      />
                    </div>
                  </div>
                  <span className="host-count">{host.count}</span>
                </div>
              ))}

              {!stats?.top_hosts.length && (
                <div className="empty-state">No reporting hosts yet.</div>
              )}
            </div>
          </article>
        </section>

        <section className="panel events-panel" id="events">
          <BandwidthTimeline />
          <LiveTraffic />
          <UnifiedEventExplorer />
          <div className="panel-header events-header">
            <div>
              <h2>Event explorer</h2>
              <p>Search and investigate recently collected telemetry.</p>
            </div>

            <span className="result-count">
              {filteredEvents.length} results
            </span>
          </div>

          <div className="event-controls">
            <label className="search-box">
              <Search size={17} />
              <input
                type="search"
                placeholder="Search host, process, IP address..."
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </label>

            <label className="severity-select">
              <span>Severity</span>
              <select
                value={severity}
                onChange={(event) => setSeverity(event.target.value)}
              >
                <option value="all">All levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </label>
          </div>

          <div className="table-scroll">
            <table className="events-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Host</th>
                  <th>Event</th>
                  <th>Connection</th>
                  <th>Process</th>
                  <th>Severity</th>
                </tr>
              </thead>

              <tbody>
                {filteredEvents.map((event) => (
                  <tr key={event.id}>
                    <td className="time-cell">{formatTime(event.timestamp)}</td>

                    <td>
                      <div className="host-cell">
                        <Server size={15} />
                        {event.hostname}
                      </div>
                    </td>

                    <td>
                      <div className="event-cell">
                        <strong>{event.event_type.replaceAll("_", " ")}</strong>
                        <span>{event.description}</span>
                      </div>
                    </td>

                    <td>
                      <div className="connection-cell">
                        <span>
                          {event.local_ip ?? "—"}:{event.local_port ?? "—"}
                        </span>
                        <ArrowRight size={13} />
                        <span>
                          {event.remote_ip ?? "—"}:{event.remote_port ?? "—"}
                        </span>
                      </div>
                    </td>

                    <td>
                      <div className="process-cell">
                        <strong>{event.process_name ?? "Unknown"}</strong>
                        <span>PID {event.process_id ?? "—"}</span>
                      </div>
                    </td>

                    <td>
                      <span className={`severity-badge ${event.severity}`}>
                        {event.severity}
                      </span>
                    </td>
                  </tr>
                ))}

                {filteredEvents.length === 0 && (
                  <tr>
                    <td colSpan={6} className="empty-table">
                      {loading
                        ? "Loading security events..."
                        : "No events match your search and filters."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="table-footer">
            <span>
              <span className="live-dot" />
              Refreshes every 5 seconds
            </span>
            <span>
              {lastUpdated
                ? `Updated ${lastUpdated.toLocaleTimeString()}`
                : "Waiting for data"}
            </span>
          </div>
        </section>

        <section className="panel alerts-panel" id="alerts">
          <div className="panel-header events-header">
            <div>
              <h2>Security alerts</h2>
              <p>Detection rule matches requiring investigation</p>
            </div>

            <span className="result-count">
              {stats?.total_alerts ?? 0} total alerts
            </span>
          </div>

          <div className="table-scroll">
            <table className="events-table">
              <thead>
                <tr>
                  <th>Detected</th>
                  <th>Rule</th>
                  <th>Host</th>
                  <th>Remote IP</th>
                  <th>Severity</th>
                </tr>
              </thead>

              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td className="time-cell">
                      {formatTime(alert.created_at)}
                    </td>

                    <td>
                      <div className="event-cell">
                        <strong>{alert.rule_id}</strong>
                        <span title={alert.description}>{alert.title}</span>
                      </div>
                    </td>

                    <td>{alert.hostname}</td>

                    <td>{alert.remote_ip ?? "—"}</td>

                    <td>
                      <span className={`severity-badge ${alert.severity}`}>
                        {alert.severity}
                      </span>
                    </td>
                  </tr>
                ))}

                {alerts.length === 0 && (
                  <tr>
                    <td colSpan={5} className="empty-table">
                      No detection alerts recorded.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <footer className="page-footer">
          <span>LinkShield SIEM · Local development</span>
          <span>
            <Bell size={13} />
            Rule engine active · LS-001
          </span>
        </footer>
      </main>
    </div>
  );
}

export default App;
