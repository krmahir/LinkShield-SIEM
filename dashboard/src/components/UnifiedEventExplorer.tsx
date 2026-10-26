import { useEffect, useState } from "react";
import "./UnifiedEventExplorer.css";

const API = import.meta.env.DEV ? "http://127.0.0.1:8001" : "";

const PAGE_SIZE = 50;

interface TimelineEvent {
  record_uid: string;
  record_id: number;
  record_type: "event" | "flow" | "alert";
  event_category: string;
  event_type: string;
  event_source: string;
  timestamp_utc: string;
  severity: string;
  hostname: string | null;
  description: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  process_name: string | null;
  direction: string | null;
  protocol: string | null;
  rule_id: string | null;
}

interface TimelineResponse {
  items: TimelineEvent[];
  has_more: boolean;
  limit: number;
  offset: number;
}

interface EventDetails {
  event: TimelineEvent;
  details: Record<string, unknown> | null;
  linked_alerts: string[];
}

function formatTime(value: string) {
  const date = new Date(value);

  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function UnifiedEventExplorer() {
  const [category, setCategory] = useState("");
  const [severity, setSeverity] = useState("");
  const [search, setSearch] = useState("");
  const [ip, setIp] = useState("");
  const [process, setProcess] = useState("");
  const [minutes, setMinutes] = useState("60");

  const [page, setPage] = useState(0);
  const [refresh, setRefresh] = useState(0);

  const [result, setResult] = useState<TimelineResponse>({
    items: [],
    has_more: false,
    limit: PAGE_SIZE,
    offset: 0,
  });

  const [selected, setSelected] = useState<TimelineEvent | null>(null);
  const [details, setDetails] = useState<EventDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Poll for new records every 10 seconds.
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (page === 0) {
        setRefresh((value) => value + 1);
      }
    }, 10000);

    return () => window.clearInterval(timer);
  }, [page]);

  // Fetch records whenever a filter changes.
  useEffect(() => {
    const controller = new AbortController();

    async function loadTimeline() {
      setLoading(true);

      try {
        const params = new URLSearchParams({
          limit: String(PAGE_SIZE),
          offset: String(page * PAGE_SIZE),
          since_minutes: minutes,
        });

        if (category) params.set("category", category);
        if (severity) params.set("severity", severity);
        if (search.trim()) params.set("search", search.trim());
        if (ip.trim()) params.set("ip", ip.trim());
        if (process.trim()) params.set("process", process.trim());

        const response = await fetch(`${API}/timeline?${params}`, {
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`Timeline API returned HTTP ${response.status}`);
        }

        const data: TimelineResponse = await response.json();

        setResult(data);
        setError("");
      } catch (err) {
        if (!controller.signal.aborted) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load security events",
          );
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      }
    }

    void loadTimeline();

    return () => controller.abort();
  }, [category, severity, search, ip, process, minutes, page, refresh]);

  // Retrieve the original record and related evidence.
  useEffect(() => {
    if (!selected) {
      setDetails(null);
      return;
    }

    const controller = new AbortController();

    async function loadDetails() {
      try {
        const response = await fetch(
          `${API}/timeline/${selected!.record_type}/${selected!.record_id}`,
          { signal: controller.signal },
        );

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const data: EventDetails = await response.json();
        setDetails(data);
      } catch (err) {
        if (!controller.signal.aborted) {
          console.error("Event details unavailable", err);
        }
      }
    }

    setDetails(null);
    void loadDetails();

    return () => controller.abort();
  }, [selected]);

  function resetPage() {
    setPage(0);
  }

  return (
    <section className="panel unified-explorer" id="unified-explorer">
      <div className="panel-header">
        <div>
          <h2>Unified Event Explorer</h2>
          <p>Network · Authentication · Process · Detection · System</p>
        </div>

        <button
          type="button"
          className="ue-button"
          onClick={() => setRefresh((value) => value + 1)}
        >
          Refresh
        </button>
      </div>

      <div className="ue-filters">
        <label>
          Category
          <select
            value={category}
            onChange={(event) => {
              setCategory(event.target.value);
              resetPage();
            }}
          >
            <option value="">All categories</option>
            <option value="network">Network</option>
            <option value="authentication">Authentication</option>
            <option value="process">Process</option>
            <option value="detection">Detection</option>
            <option value="system">System</option>
          </select>
        </label>

        <label>
          Severity
          <select
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
              resetPage();
            }}
          >
            <option value="">All severities</option>
            <option value="info">Info</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </label>

        <label>
          Time range
          <select
            value={minutes}
            onChange={(event) => {
              setMinutes(event.target.value);
              resetPage();
            }}
          >
            <option value="15">Last 15 minutes</option>
            <option value="60">Last hour</option>
            <option value="360">Last 6 hours</option>
            <option value="1440">Last 24 hours</option>
            <option value="10080">Last 7 days</option>
          </select>
        </label>

        <label>
          IP address
          <input
            placeholder="Source or destination"
            value={ip}
            onChange={(event) => {
              setIp(event.target.value);
              resetPage();
            }}
          />
        </label>

        <label>
          Process
          <input
            placeholder="e.g. firefox.exe"
            value={process}
            onChange={(event) => {
              setProcess(event.target.value);
              resetPage();
            }}
          />
        </label>

        <label>
          Search all fields
          <input
            placeholder="Event, hostname, rule, IP..."
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              resetPage();
            }}
          />
        </label>
      </div>

      <div className="ue-toolbar">
        <span>
          {loading
            ? "Loading events..."
            : `Showing ${result.items.length} records`}
          {page > 0 && ` · Page ${page + 1}`}
        </span>

        <button
          type="button"
          className="ue-button"
          onClick={() => {
            setCategory("");
            setSeverity("");
            setSearch("");
            setIp("");
            setProcess("");
            setMinutes("60");
            setPage(0);
          }}
        >
          Clear filters
        </button>
      </div>

      {error && <p className="ue-error">{error}</p>}

      <div className="table-scroll">
        <table className="events-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Category</th>
              <th>Event</th>
              <th>Severity</th>
              <th>Host / Process</th>
              <th>Source IP</th>
              <th>Destination IP</th>
              <th>Details</th>
            </tr>
          </thead>

          <tbody>
            {result.items.map((event) => (
              <tr key={event.record_uid}>
                <td>{formatTime(event.timestamp_utc)}</td>

                <td>
                  <span className="ue-category">{event.event_category}</span>
                </td>

                <td>
                  <strong>{event.event_type}</strong>
                  <div className="ue-description">
                    {event.description ?? "—"}
                  </div>
                </td>

                <td>
                  <span className={`ue-severity ue-${event.severity}`}>
                    {event.severity}
                  </span>
                </td>

                <td>
                  {event.hostname ?? "—"}
                  <div className="ue-description">
                    {event.process_name ?? "Unknown process"}
                  </div>
                </td>

                <td>{event.src_ip ?? "—"}</td>
                <td>{event.dst_ip ?? "—"}</td>

                <td>
                  <button
                    type="button"
                    className="ue-button"
                    onClick={() => setSelected(event)}
                  >
                    Investigate
                  </button>
                </td>
              </tr>
            ))}

            {!loading && result.items.length === 0 && (
              <tr>
                <td colSpan={8} className="empty-table">
                  No events match the selected filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="ue-pagination">
        <button
          type="button"
          className="ue-button"
          disabled={page === 0}
          onClick={() => setPage((value) => Math.max(0, value - 1))}
        >
          Previous
        </button>

        <span>Page {page + 1}</span>

        <button
          type="button"
          className="ue-button"
          disabled={!result.has_more}
          onClick={() => setPage((value) => value + 1)}
        >
          Next
        </button>
      </div>

      {selected && (
        <div className="ue-details">
          <div className="ue-details-header">
            <div>
              <h3>Event Investigation</h3>
              <p>{selected.record_uid}</p>
            </div>

            <button
              type="button"
              className="ue-button"
              onClick={() => setSelected(null)}
            >
              Close
            </button>
          </div>

          <p>
            <strong>Category:</strong> {selected.event_category}
            {" · "}
            <strong>Source:</strong> {selected.event_source}
          </p>

          <p>
            <strong>Description:</strong>{" "}
            {selected.description ?? "No description"}
          </p>

          <h4>Original event evidence</h4>

          <pre className="ue-json">
            {details
              ? JSON.stringify(details.details, null, 2)
              : "Loading event details..."}
          </pre>

          {details && details.linked_alerts.length > 0 && (
            <p>
              <strong>Related alerts:</strong>{" "}
              {details.linked_alerts.join(", ")}
            </p>
          )}

          {selected.rule_id && (
            <p>
              <strong>Detection rule:</strong> {selected.rule_id}
            </p>
          )}
        </div>
      )}
    </section>
  );
}
