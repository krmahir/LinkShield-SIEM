import { useEffect, useState } from "react";
import { CircleMarker, MapContainer, Popup, TileLayer } from "react-leaflet";
import countries from "world-countries";

import "leaflet/dist/leaflet.css";
import "./TrafficMap.css";

const API = "http://127.0.0.1:8001";

type Direction = "inbound" | "outbound";

interface GeoFlow {
  remote_ip: string;
  country: string | null;
  country_code: string;
  direction: Direction;
  flow_count: number;
  packet_count: number;
  byte_count: number;
}

interface GeoResponse {
  period: string;
  location_precision: string;
  locations: GeoFlow[];
}

interface CountryTraffic {
  country_code: string;
  country: string;
  latitude: number;
  longitude: number;

  inbound_packets: number;
  outbound_packets: number;

  inbound_bytes: number;
  outbound_bytes: number;

  unique_ips: number;
}

const countryLookup = new Map(
  countries.map((country) => [country.cca2, country.latlng]),
);

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;

  if (bytes < 1024 ** 2) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return `${(bytes / 1024 ** 2).toFixed(2)} MB`;
}

function groupByCountry(flows: GeoFlow[]): CountryTraffic[] {
  const grouped = new Map<string, CountryTraffic & { ips: Set<string> }>();

  for (const flow of flows) {
    const coordinates = countryLookup.get(flow.country_code);

    if (!coordinates) continue;

    let country = grouped.get(flow.country_code);

    if (!country) {
      country = {
        country_code: flow.country_code,
        country: flow.country || flow.country_code,
        latitude: coordinates[0],
        longitude: coordinates[1],
        inbound_packets: 0,
        outbound_packets: 0,
        inbound_bytes: 0,
        outbound_bytes: 0,
        unique_ips: 0,
        ips: new Set<string>(),
      };

      grouped.set(flow.country_code, country);
    }

    country.ips.add(flow.remote_ip);

    if (flow.direction === "inbound") {
      country.inbound_packets += flow.packet_count;
      country.inbound_bytes += flow.byte_count;
    } else {
      country.outbound_packets += flow.packet_count;
      country.outbound_bytes += flow.byte_count;
    }
  }

  return Array.from(grouped.values()).map(({ ips, ...country }) => ({
    ...country,
    unique_ips: ips.size,
  }));
}

function markerColor(country: CountryTraffic): string {
  if (country.inbound_packets > 0 && country.outbound_packets > 0) {
    return "#a78bfa";
  }

  if (country.inbound_packets > 0) {
    return "#34d399";
  }

  return "#60a5fa";
}

export default function TrafficMap() {
  const [locations, setLocations] = useState<CountryTraffic[]>([]);

  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;

    async function loadTraffic() {
      try {
        const response = await fetch(`${API}/geo/traffic`);

        if (!response.ok) {
          throw new Error(`Geolocation API returned HTTP ${response.status}`);
        }

        const data: GeoResponse = await response.json();
        const grouped = groupByCountry(data.locations);

        if (active) {
          setLocations(grouped);
          setError("");
        }
      } catch (err) {
        if (active) {
          setError(
            err instanceof Error ? err.message : "Unable to load traffic",
          );
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    void loadTraffic();

    const timer = window.setInterval(() => {
      void loadTraffic();
    }, 15000);

    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <section className="geo-panel" id="geo-map">
      <div className="geo-header">
        <div>
          <h2>Network Activity Map</h2>
          <p>Inbound and outbound traffic · Last 24 hours</p>
        </div>

        <span>{locations.length} countries</span>
      </div>

      <div className="traffic-map-legend">
        <span style={{ color: "#60a5fa" }}>● Outbound</span>
        <span style={{ color: "#34d399" }}>● Inbound</span>
        <span style={{ color: "#a78bfa" }}>● Both</span>
      </div>

      {error && <p className="geo-error">{error}</p>}

      {loading && <p className="geo-status">Loading network traffic...</p>}

      <MapContainer
        center={[25, 20]}
        zoom={2}
        minZoom={2}
        scrollWheelZoom={false}
        className="geo-map"
        style={{ height: "320px", width: "100%" }}
      >
        <TileLayer
          attribution="&copy; OpenStreetMap contributors"
          url="https://tile.openstreetmap.org/{z}/{x}/{y}.png"
        />

        {locations.map((country) => {
          const totalPackets =
            country.inbound_packets + country.outbound_packets;

          const color = markerColor(country);

          return (
            <CircleMarker
              key={country.country_code}
              center={[country.latitude, country.longitude]}
              radius={Math.min(18, 5 + Math.log10(totalPackets + 1) * 3)}
              pathOptions={{
                color,
                fillColor: color,
                fillOpacity: 0.65,
                weight: 1,
              }}
            >
              <Popup>
                <strong>{country.country}</strong>

                <div>Unique remote IPs: {country.unique_ips}</div>

                <hr />

                <div>Inbound packets: {country.inbound_packets}</div>

                <div>Inbound bytes: {formatBytes(country.inbound_bytes)}</div>

                <div>Outbound packets: {country.outbound_packets}</div>

                <div>Outbound bytes: {formatBytes(country.outbound_bytes)}</div>

                <hr />

                <small>Country-level approximation only.</small>
              </Popup>
            </CircleMarker>
          );
        })}
      </MapContainer>

      {!loading && !error && locations.length === 0 && (
        <p className="geo-status">No geolocatable public IP traffic found.</p>
      )}
    </section>
  );
}
