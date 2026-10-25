import { useEffect, useState } from "react";

const API = "http://127.0.0.1:8001";

interface Investigation {
  ip: string;
  period_minutes: number;

  summary: {
    flow_records: number;
    inbound_packets: number;
    outbound_packets: number;
    inbound_bytes: number;
    outbound_bytes: number;
    last_seen: string | null;
  };

  protocols: {
    protocol: string;
    packets: number;
    bytes: number;
  }[];

  flows: {
    id: number;
    direction: string;
    protocol: string;
    src_ip: string;
    src_port: number | null;
    dst_ip: string;
    dst_port: number | null;
    packet_count: number;
    byte_count: number;
    dns_query: string | null;
    received_at: string;
  }[];
}

interface Props {
  ip: string | null;
  onClose: () => void;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;

  if (bytes < 1048576) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return `${(bytes / 1048576).toFixed(2)} MB`;
}

export default function EndpointInspector({ ip, onClose }: Props) {
  const [data, setData] = useState<Investigation | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!ip) return;

    const targetIp: string = ip;
    let active = true;

    setData(null);
    setLoading(true);
    setError("");

    async function refresh() {
      try {
        const response = await fetch(
          `${API}/flows/investigate?ip=${encodeURIComponent(targetIp)}&minutes=60`,
        );

        if (!response.ok) {
          throw new Error(
            `Investigation request failed: HTTP ${response.status}`,
          );
        }

        const result: Investigation = await response.json();

        if (active) {
          setData(result);
          setError("");
        }
      } catch (err) {
        if (active) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to investigate endpoint",
          );
        }
      } finally {
        if (active) setLoading(false);
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
  }, [ip]);

  if (!ip) return null;

  return (
    <section className="endpoint-inspector">
      <div className="endpoint-header">
        <div>
          <h3>IP Investigation</h3>
          <p>{ip} · Last 60 minutes · Auto-refresh</p>
        </div>

        <button type="button" onClick={onClose} className="endpoint-close">
          Close
        </button>
      </div>

      {loading && !data && <p>Loading endpoint activity...</p>}

      {error && <p className="traffic-error">{error}</p>}

      {data && (
        <>
          <div className="endpoint-stats">
            <div>
              <span>Inbound</span>
              <strong>{formatBytes(data.summary.inbound_bytes)}</strong>
              <small>
                {data.summary.inbound_packets.toLocaleString()} packets
              </small>
            </div>

            <div>
              <span>Outbound</span>
              <strong>{formatBytes(data.summary.outbound_bytes)}</strong>
              <small>
                {data.summary.outbound_packets.toLocaleString()} packets
              </small>
            </div>

            <div>
              <span>Flow summaries</span>
              <strong>{data.summary.flow_records.toLocaleString()}</strong>
              <small>
                Last seen:{" "}
                {data.summary.last_seen
                  ? new Date(data.summary.last_seen).toLocaleTimeString()
                  : "Never"}
              </small>
            </div>
          </div>

          <h4>Observed Protocols</h4>

          <div className="endpoint-protocols">
            {data.protocols.map((protocol) => (
              <div key={protocol.protocol}>
                <strong>{protocol.protocol}</strong>
                <span>{protocol.packets.toLocaleString()} packets</span>
                <span>{formatBytes(protocol.bytes)}</span>
              </div>
            ))}
          </div>

          <h4>Recent Transmissions</h4>

          <div className="table-scroll">
            <table className="events-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Direction</th>
                  <th>Protocol</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Packets</th>
                  <th>Bytes</th>
                </tr>
              </thead>

              <tbody>
                {data.flows.map((flow) => (
                  <tr key={flow.id}>
                    <td>{new Date(flow.received_at).toLocaleTimeString()}</td>
                    <td>{flow.direction}</td>
                    <td>{flow.protocol}</td>
                    <td>
                      {flow.src_ip}:{flow.src_port ?? "—"}
                    </td>
                    <td>
                      {flow.dst_ip}:{flow.dst_port ?? "—"}
                    </td>
                    <td>{flow.packet_count}</td>
                    <td>{formatBytes(flow.byte_count)}</td>
                  </tr>
                ))}

                {data.flows.length === 0 && (
                  <tr>
                    <td colSpan={7}>No activity found in the last hour.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}
