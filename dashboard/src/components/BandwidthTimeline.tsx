import { useEffect, useState } from "react";

import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const API = "http://127.0.0.1:8001";

interface TimelinePoint {
  timestamp: string;
  inbound_bytes: number;
  outbound_bytes: number;
  inbound_packets: number;
  outbound_packets: number;
}

interface TimelineResponse {
  period_minutes: number;
  bucket_seconds: number;
  points: TimelinePoint[];
}

interface ChartPoint {
  timestamp: string;
  inbound: number;
  outbound: number;
}

function formatTime(value: string): string {
  return new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function BandwidthTimeline() {
  const [points, setPoints] = useState<ChartPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;

    async function loadTimeline() {
      try {
        const response = await fetch(`${API}/flows/timeline?minutes=15`);

        if (!response.ok) {
          throw new Error(`Timeline API returned HTTP ${response.status}`);
        }

        const data: TimelineResponse = await response.json();

        const chartPoints = data.points.map((point) => ({
          timestamp: point.timestamp,

          // Convert bytes per bucket to KiB per second.
          inbound: point.inbound_bytes / data.bucket_seconds / 1024,

          outbound: point.outbound_bytes / data.bucket_seconds / 1024,
        }));

        if (active) {
          setPoints(chartPoints);
          setError("");
        }
      } catch (err) {
        if (active) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load bandwidth timeline",
          );
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    void loadTimeline();

    const interval = window.setInterval(() => {
      void loadTimeline();
    }, 5000);

    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, []);

  const hasTraffic = points.some(
    (point) => point.inbound > 0 || point.outbound > 0,
  );

  return (
    <section className="panel bandwidth-panel">
      <div className="panel-header">
        <div>
          <h2>Network Throughput</h2>
          <p>Inbound and outbound traffic · Last 15 minutes</p>
        </div>
        <span className="bandwidth-live-label">Refreshing every 5s</span>
      </div>

      {error && <p className="traffic-error">{error}</p>}

      {loading && (
        <p className="bandwidth-status">Loading bandwidth history...</p>
      )}

      {!loading && !error && !hasTraffic && (
        <p className="bandwidth-status">
          No network activity recorded during this period.
        </p>
      )}

      <div className="bandwidth-chart">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={points}>
            <defs>
              <linearGradient
                id="linkshieldInbound"
                x1="0"
                y1="0"
                x2="0"
                y2="1"
              >
                <stop offset="0%" stopColor="#34d399" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#34d399" stopOpacity={0} />
              </linearGradient>

              <linearGradient
                id="linkshieldOutbound"
                x1="0"
                y1="0"
                x2="0"
                y2="1"
              >
                <stop offset="0%" stopColor="#60a5fa" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#60a5fa" stopOpacity={0} />
              </linearGradient>
            </defs>

            <CartesianGrid
              stroke="#29374a"
              strokeDasharray="3 3"
              vertical={false}
            />

            <XAxis
              dataKey="timestamp"
              tickFormatter={formatTime}
              stroke="#94a3b8"
              tick={{ fontSize: 11 }}
              minTickGap={35}
            />

            <YAxis
              stroke="#94a3b8"
              tick={{ fontSize: 11 }}
              width={50}
              tickFormatter={(value: number) => value.toFixed(0)}
              label={{
                value: "KiB/s",
                angle: -90,
                position: "insideLeft",
                fill: "#94a3b8",
                fontSize: 11,
              }}
            />

            <Tooltip
              labelFormatter={(label) => formatTime(String(label))}
              formatter={(value) => `${Number(value ?? 0).toFixed(2)} KiB/s`}
              contentStyle={{
                background: "#172334",
                border: "1px solid #334155",
                borderRadius: 8,
                color: "#e2e8f0",
              }}
            />

            <Legend />

            <Area
              type="monotone"
              name="Inbound"
              dataKey="inbound"
              stroke="#34d399"
              strokeWidth={2}
              fill="url(#linkshieldInbound)"
              dot={false}
              isAnimationActive={false}
            />

            <Area
              type="monotone"
              name="Outbound"
              dataKey="outbound"
              stroke="#60a5fa"
              strokeWidth={2}
              fill="url(#linkshieldOutbound)"
              dot={false}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
