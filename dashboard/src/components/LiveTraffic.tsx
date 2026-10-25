import { useEffect, useState } from "react";

import EndpointInspector from "./EndpointInspector";

const API = "http://127.0.0.1:8001";

interface Flow {
  id: number;
  hostname: string;
  direction: string;
  protocol: string;
  src_ip: string;
  src_port: number | null;
  dst_ip: string;
  dst_port: number | null;
  packet_count: number;
  byte_count: number;
  dns_query: string | null;
  observed_dns_name: string | null;
  received_at: string;
  process_name: string | null;
  process_id: number | null;
}

interface FlowStats {
  period_seconds: number;
  inbound_bytes: number;
  outbound_bytes: number;
  total_packets: number;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / 1024 ** 2).toFixed(2)} MB`;
}

export default function LiveTraffic() {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [stats, setStats] = useState<FlowStats | null>(null);
  const [error, setError] = useState("");
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [directionFilter, setDirectionFilter] = useState("all");
  const [protocolFilter, setProtocolFilter] = useState("all");

  useEffect(() => {
    let active = true;

    async function refresh() {
      try {
        const params = new URLSearchParams({
          limit: "100",
        });

        if (search.trim()) {
          params.set("search", search.trim());
        }

        if (directionFilter !== "all") {
          params.set("direction", directionFilter);
        }

        if (protocolFilter !== "all") {
          params.set("protocol", protocolFilter);
        }
        const [flowResponse, statsResponse] = await Promise.all([
          fetch(`${API}/flows?${params.toString()}`),
          fetch(`${API}/flows/stats`),
        ]);

        if (!flowResponse.ok || !statsResponse.ok) {
          throw new Error("Flow API request failed");
        }

        const nextFlows: Flow[] = await flowResponse.json();
        const nextStats: FlowStats = await statsResponse.json();

        if (active) {
          setFlows(nextFlows);
          setStats(nextStats);
          setError("");
        }
      } catch (err) {
        if (active) {
          setError(err instanceof Error ? err.message : "Failed to load flows");
        }
      }
    }

    void refresh();

    const timer = window.setInterval(() => {
      void refresh();
    }, 5000);

    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [search, directionFilter, protocolFilter]);

  return (
    <section className="panel live-traffic-panel" id="live-traffic">
      <div className="panel-header">
        <div>
          <h2>Live Network Traffic</h2>
          <p>Packet flow summaries · Refreshes every 5 seconds</p>
        </div>
      </div>

      <div className="traffic-stats">
        <div>
          <span>Inbound · Last 60s</span>
          <strong>{formatBytes(stats?.inbound_bytes ?? 0)}</strong>
        </div>
        <div>
          <span>Outbound · Last 60s</span>
          <strong>{formatBytes(stats?.outbound_bytes ?? 0)}</strong>
        </div>
        <div>
          <span>Packets · Last 60s</span>
          <strong>{(stats?.total_packets ?? 0).toLocaleString()}</strong>
        </div>
      </div>

      {error && <p className="traffic-error">{error}</p>}

      <div className="traffic-filters">
        <input
          type="search"
          aria-label="Search network traffic"
          placeholder="Search IP, application, DNS or host..."
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />

        <select
          aria-label="Filter traffic direction"
          value={directionFilter}
          onChange={(event) => setDirectionFilter(event.target.value)}
        >
          <option value="all">All directions</option>
          <option value="inbound">Inbound</option>
          <option value="outbound">Outbound</option>
          <option value="other">Other</option>
        </select>

        <select
          aria-label="Filter network protocol"
          value={protocolFilter}
          onChange={(event) => setProtocolFilter(event.target.value)}
        >
          <option value="all">All protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="ICMP">ICMP</option>
          <option value="ARP">ARP</option>
          <option value="OTHER">Other</option>
        </select>

        <button
          type="button"
          onClick={() => {
            setSearch("");
            setDirectionFilter("all");
            setProtocolFilter("all");
          }}
        >
          Clear
        </button>
      </div>

      <div className="table-scroll">
        <table className="events-table">
          <thead>
            <tr>
              <th>Direction</th>
              <th>Protocol</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Packets</th>
              <th>Bytes</th>
              <th>DNS observation</th>
              <th>Investigate</th>
              <th>Application</th>
            </tr>
          </thead>

          <tbody>
            {flows.map((flow) => (
              <tr key={flow.id}>
                <td>
                  <span className={`direction-label ${flow.direction}`}>
                    {flow.direction}
                  </span>
                </td>
                <td>{flow.protocol}</td>
                <td>
                  {flow.src_ip}:{flow.src_port ?? "—"}
                </td>
                <td>
                  {flow.dst_ip}:{flow.dst_port ?? "—"}
                </td>
                <td>{flow.packet_count}</td>
                <td>{formatBytes(flow.byte_count)}</td>
                <td>
                  {flow.observed_dns_name ? (
                    <span title="Observed DNS answer for this IP; not proof this connection used the domain">
                      {flow.observed_dns_name} (DNS match)
                    </span>
                  ) : flow.dns_query ? (
                    <span>Query: {flow.dns_query}</span>
                  ) : (
                    "—"
                  )}
                </td>
                <td>
                  {flow.direction === "other" ? (
                    "—"
                  ) : (
                    <button
                      type="button"
                      className="inspect-flow-btn"
                      onClick={() =>
                        setSelectedIp(
                          flow.direction === "inbound"
                            ? flow.src_ip
                            : flow.dst_ip,
                        )
                      }
                    >
                      Investigate
                    </button>
                  )}
                </td>
                <td>
                  {flow.process_name ? (
                    <>
                      <strong>{flow.process_name}</strong>
                      {flow.process_id !== null && (
                        <div>PID {flow.process_id}</div>
                      )}
                    </>
                  ) : (
                    "Unknown"
                  )}
                </td>
              </tr>
            ))}

            {flows.length === 0 && (
              <tr>
                <td colSpan={9} className="empty-table">
                  No network flows collected yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <EndpointInspector ip={selectedIp} onClose={() => setSelectedIp(null)} />
    </section>
  );
}
