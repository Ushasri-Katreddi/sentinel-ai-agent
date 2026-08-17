import { useEffect, useMemo, useState } from "react";
import {
  BarChart3,
  ShieldAlert,
  Globe,
  Activity,
} from "lucide-react";

import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

import { getThreats } from "../services/threatService";
import type { Threat } from "../types/threat";

function Analytics() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadThreats = async () => {
      try {
        setLoading(true);

        const data = await getThreats();

        setThreats(data);
      } catch (err) {
        console.error(err);
        setError("Unable to load analytics data.");
      } finally {
        setLoading(false);
      }
    };

    loadThreats();
  }, []);

  const severityData = useMemo(() => {
    const counts: Record<string, number> = {};

    threats.forEach((threat) => {
      const severity =
        threat.severity?.toUpperCase() || "UNKNOWN";

      counts[severity] = (counts[severity] || 0) + 1;
    });

    return Object.entries(counts).map(
      ([name, value]) => ({
        name,
        value,
      })
    );
  }, [threats]);

  const maliciousData = useMemo(() => {
    const malicious = threats.filter(
      (threat) => threat.malicious_ip
    ).length;

    const safe = threats.length - malicious;

    return [
      {
        name: "Malicious",
        value: malicious,
      },
      {
        name: "Safe",
        value: safe,
      },
    ];
  }, [threats]);

  const intelligenceData = useMemo(() => {
    const counts: Record<string, number> = {};

    threats.forEach((threat) => {
      const source =
        threat.intelligence_source || "Unknown";

      counts[source] = (counts[source] || 0) + 1;
    });

    return Object.entries(counts).map(
      ([name, value]) => ({
        name,
        value,
      })
    );
  }, [threats]);

  const attackData = useMemo(() => {
    const counts: Record<string, number> = {};

    threats.forEach((threat) => {
      const attack =
        threat.attack || "Unknown";

      counts[attack] = (counts[attack] || 0) + 1;
    });

    return Object.entries(counts).map(
      ([name, value]) => ({
        name,
        value,
      })
    );
  }, [threats]);

  const scoreData = useMemo(() => {
    return threats.map((threat, index) => ({
      name: `Threat ${index + 1}`,
      score: threat.score,
    }));
  }, [threats]);

  const averageScore = useMemo(() => {
    if (!threats.length) {
      return 0;
    }

    const total = threats.reduce(
      (sum, threat) => sum + threat.score,
      0
    );

    return Math.round(total / threats.length);
  }, [threats]);

  const criticalThreats = threats.filter(
    (threat) =>
      threat.severity?.toUpperCase() === "CRITICAL"
  ).length;

  const maliciousIPs = threats.filter(
    (threat) => threat.malicious_ip
  ).length;

  if (loading) {
    return (
      <div className="page">
        <div className="loading-state">
          Loading analytics...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page">
        <div className="dashboard-error">
          {error}
        </div>
      </div>
    );
  }

  return (
    <div className="page">

      {/* HEADER */}

      <div className="page-header">

        <div>
          <h1>Security Analytics</h1>

          <p>
            Threat intelligence and security event analysis
          </p>
        </div>

      </div>


      {/* SUMMARY CARDS */}

      <div className="analytics-summary">

        <div className="analytics-card">

          <div className="analytics-card-icon">
            <Activity size={22} />
          </div>

          <div>
            <span>Total Threats</span>
            <strong>{threats.length}</strong>
          </div>

        </div>


        <div className="analytics-card">

          <div className="analytics-card-icon">
            <ShieldAlert size={22} />
          </div>

          <div>
            <span>Critical Threats</span>
            <strong>{criticalThreats}</strong>
          </div>

        </div>


        <div className="analytics-card">

          <div className="analytics-card-icon">
            <Globe size={22} />
          </div>

          <div>
            <span>Malicious IPs</span>
            <strong>{maliciousIPs}</strong>
          </div>

        </div>


        <div className="analytics-card">

          <div className="analytics-card-icon">
            <BarChart3 size={22} />
          </div>

          <div>
            <span>Average Score</span>
            <strong>{averageScore}</strong>
          </div>

        </div>

      </div>


      {/* CHART GRID */}

      <div className="analytics-grid">

        {/* SEVERITY */}

        <div className="analytics-chart-card">

          <div className="analytics-chart-header">

            <div>
              <h2>Threat Severity</h2>
              <p>Distribution by severity level</p>
            </div>

          </div>

          <div className="chart-container">

            <ResponsiveContainer
              width="100%"
              height="100%"
            >

              <BarChart data={severityData}>

                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#26334d"
                />

                <XAxis
                  dataKey="name"
                  stroke="#71809c"
                />

                <YAxis
                  allowDecimals={false}
                  stroke="#71809c"
                />

                <Tooltip />

                <Bar
                  dataKey="value"
                  fill="#3b82f6"
                  radius={[6, 6, 0, 0]}
                />

              </BarChart>

            </ResponsiveContainer>

          </div>

        </div>


        {/* MALICIOUS IP */}

        <div className="analytics-chart-card">

          <div className="analytics-chart-header">

            <div>
              <h2>IP Reputation</h2>
              <p>Malicious versus safe indicators</p>
            </div>

          </div>

          <div className="chart-container">

            <ResponsiveContainer
              width="100%"
              height="100%"
            >

              <PieChart>

                <Pie
                  data={maliciousData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  label
                >

                  {maliciousData.map(
                    (_, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={
                          index === 0
                            ? "#ef4444"
                            : "#22c55e"
                        }
                      />
                    )
                  )}

                </Pie>

                <Tooltip />

                <Legend />

              </PieChart>

            </ResponsiveContainer>

          </div>

        </div>


        {/* ATTACK TYPES */}

        <div className="analytics-chart-card">

          <div className="analytics-chart-header">

            <div>
              <h2>Attack Types</h2>
              <p>Detected attack classification</p>
            </div>

          </div>

          <div className="chart-container">

            <ResponsiveContainer
              width="100%"
              height="100%"
            >

              <BarChart
                data={attackData}
                layout="vertical"
              >

                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#26334d"
                />

                <XAxis
                  type="number"
                  allowDecimals={false}
                  stroke="#71809c"
                />

                <YAxis
                  type="category"
                  dataKey="name"
                  width={100}
                  stroke="#71809c"
                />

                <Tooltip />

                <Bar
                  dataKey="value"
                  fill="#8b5cf6"
                  radius={[0, 6, 6, 0]}
                />

              </BarChart>

            </ResponsiveContainer>

          </div>

        </div>


        {/* INTELLIGENCE SOURCES */}

        <div className="analytics-chart-card">

          <div className="analytics-chart-header">

            <div>
              <h2>Intelligence Sources</h2>
              <p>IOC intelligence providers</p>
            </div>

          </div>

          <div className="chart-container">

            <ResponsiveContainer
              width="100%"
              height="100%"
            >

              <PieChart>

                <Pie
                  data={intelligenceData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  label
                >

                  {intelligenceData.map(
                    (_, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={
                          [
                            "#3b82f6",
                            "#8b5cf6",
                            "#06b6d4",
                            "#f59e0b",
                          ][index % 4]
                        }
                      />
                    )
                  )}

                </Pie>

                <Tooltip />

                <Legend />

              </PieChart>

            </ResponsiveContainer>

          </div>

        </div>


        {/* THREAT SCORES */}

        <div className="analytics-chart-card analytics-wide">

          <div className="analytics-chart-header">

            <div>
              <h2>Threat Score Distribution</h2>
              <p>Threat scores across analyzed events</p>
            </div>

          </div>

          <div className="chart-container">

            <ResponsiveContainer
              width="100%"
              height="100%"
            >

              <BarChart data={scoreData}>

                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#26334d"
                />

                <XAxis
                  dataKey="name"
                  stroke="#71809c"
                />

                <YAxis
                  stroke="#71809c"
                />

                <Tooltip />

                <Bar
                  dataKey="score"
                  fill="#06b6d4"
                  radius={[6, 6, 0, 0]}
                />

              </BarChart>

            </ResponsiveContainer>

          </div>

        </div>

      </div>

    </div>
  );
}

export default Analytics;