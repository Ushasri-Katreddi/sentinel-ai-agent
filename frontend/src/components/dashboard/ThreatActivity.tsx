import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

import type { Threat } from "../../types/threat";

interface ThreatActivityProps {
  threats: Threat[];
}

function ThreatActivity({ threats }: ThreatActivityProps) {
  /*
   * Convert the threats received from the backend
   * into the format required by Recharts.
   *
   * Example:
   * Backend:
   * {
   *   timestamp: "2026-08-10T21:30:00",
   *   score: 140
   * }
   *
   * Becomes:
   * {
   *   time: "09:30 PM",
   *   score: 140
   * }
   */
  const data = threats
    .slice()
    .sort(
      (a, b) =>
        new Date(a.timestamp).getTime() -
        new Date(b.timestamp).getTime()
    )
    .map((threat) => ({
      time: new Date(threat.timestamp).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
      score: threat.score,
    }));

  return (
    <div className="chart-card">
      <div className="chart-header">
        <div>
          <h2>Threat Activity</h2>
          <p>Threat score over time</p>
        </div>
      </div>

      <div className="chart-container">
        {data.length === 0 ? (
          <div className="empty-chart">
            No threat activity available
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <LineChart
              data={data}
              margin={{
                top: 10,
                right: 20,
                left: 0,
                bottom: 10,
              }}
            >
              <CartesianGrid strokeDasharray="3 3" />

              <XAxis
                dataKey="time"
                tick={{ fontSize: 12 }}
              />

              <YAxis
                domain={[0, "auto"]}
                tick={{ fontSize: 12 }}
              />

              <Tooltip />

              <Line
                type="monotone"
                dataKey="score"
                stroke="#3b82f6"
                strokeWidth={3}
                dot={{ r: 4 }}
                activeDot={{ r: 6 }}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}

export default ThreatActivity;