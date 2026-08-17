import { useEffect, useMemo, useState } from "react";
import { RefreshCw, Search, ShieldAlert } from "lucide-react";

import { getThreats } from "../services/threatService";
import type { Threat } from "../types/threat";
import ThreatDetails from "../components/dashboard/ThreatDetails";

function Threats() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);

  const fetchThreats = async () => {
    try {
      setLoading(true);
      setError("");

      const data = await getThreats();
      setThreats(data);
    } catch (err) {
      console.error(err);
      setError("Unable to load threat intelligence.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, []);

  const filteredThreats = useMemo(() => {
    const query = search.toLowerCase().trim();

    if (!query) {
      return threats;
    }

    return threats.filter((threat) =>
      [
        threat.source_ip,
        threat.attack,
        threat.severity,
        threat.intelligence_source,
        threat.ioc_country,
      ]
        .filter(Boolean)
        .some((value) =>
          String(value).toLowerCase().includes(query)
        )
    );
  }, [threats, search]);

  return (
    <div className="page">

      {/* PAGE HEADER */}
      <div className="page-header">

        <div>
          <h1>Threat Intelligence</h1>

          <p>
            Detected cybersecurity threats and IOC intelligence
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={fetchThreats}
          disabled={loading}
        >
          <RefreshCw size={18} />
          Refresh
        </button>

      </div>


      {/* SEARCH */}
      <div className="threat-toolbar">

        <div className="search-box">

          <Search size={20} />

          <input
            type="text"
            placeholder="Search IP, attack, severity..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />

        </div>

        <span className="threat-count">
          {filteredThreats.length} Threat
          {filteredThreats.length !== 1 ? "s" : ""}
        </span>

      </div>


      {/* ERROR */}
      {error && (
        <div className="dashboard-error">
          {error}
        </div>
      )}


      {/* LOADING */}
      {loading && (
        <div className="loading-state">
          Loading threat intelligence...
        </div>
      )}


      {/* THREAT TABLE */}
      {!loading && !error && (
        <div className="threat-table-card">

          <div className="table-header">

            <div>
              <h2>Detected Threats</h2>

              <p>
                Security events analyzed by Sentinel AI
              </p>
            </div>

            <ShieldAlert size={24} />

          </div>


          <div className="table-wrapper">

            <table>

              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Source IP</th>
                  <th>Attack</th>
                  <th>Score</th>
                  <th>Malicious IP</th>
                  <th>Country</th>
                  <th>Intelligence</th>
                </tr>
              </thead>


              <tbody>

                {filteredThreats.map((threat) => (

                  <tr
                    key={threat.id}
                    onClick={() => setSelectedThreat(threat)}
                    className="threat-row"
                  >

                    <td>

                      <span
                        className={`severity-badge ${threat.severity?.toLowerCase()}`}
                      >
                        {threat.severity}
                      </span>

                    </td>


                    <td className="ip-address">
                      {threat.source_ip}
                    </td>


                    <td>
                      {threat.attack || "Unknown"}
                    </td>


                    <td className="threat-score">
                      {threat.score}
                    </td>


                    <td>

                      <span
                        className={
                          threat.malicious_ip
                            ? "malicious-yes"
                            : "malicious-no"
                        }
                      >
                        {threat.malicious_ip ? "YES" : "NO"}
                      </span>

                    </td>


                    <td>
                      {threat.ioc_country ||
                        threat.country ||
                        "Unknown"}
                    </td>


                    <td className="intelligence-source">
                      {threat.intelligence_source ||
                        "Unknown"}
                    </td>

                  </tr>

                ))}

              </tbody>

            </table>


            {filteredThreats.length === 0 && (
              <div className="empty-state">
                No threats found.
              </div>
            )}

          </div>

        </div>
      )}


      {/* THREAT DETAILS DRAWER */}
      {selectedThreat && (
        <ThreatDetails
          threat={selectedThreat}
          onClose={() => setSelectedThreat(null)}
        />
      )}

    </div>
  );
}

export default Threats;