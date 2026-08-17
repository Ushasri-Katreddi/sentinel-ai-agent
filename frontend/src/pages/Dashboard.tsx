import { useEffect, useState } from "react";
import ThreatSummary from "../components/dashboard/ThreatSummary";
import ThreatActivity from "../components/dashboard/ThreatActivity";
import { getThreats } from "../services/threatService";
import type { Threat } from "../types/threat";

function Dashboard() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const data = await getThreats();

        setThreats(data);
      } catch (err) {
        console.error("Failed to fetch threats:", err);
        setError("Unable to connect to Sentinel AI backend.");
      } finally {
        setLoading(false);
      }
    };

    fetchThreats();
  }, []);

  return (
    <div>
      <div className="dashboard-heading">
        <h1>Sentinel AI Dashboard</h1>

        <p>
          Autonomous Cybersecurity Threat Intelligence
        </p>
      </div>

      {loading && (
        <p className="dashboard-status">
          Loading threat intelligence...
        </p>
      )}

      {error && (
        <p className="dashboard-error">
          {error}
        </p>
      )}

      {!loading && !error && (
        <>
          <ThreatSummary threats={threats} />

          <ThreatActivity threats={threats} />
        </>
      )}
    </div>
  );
}

export default Dashboard;