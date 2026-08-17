import { useEffect, useMemo, useState } from "react";
import {
  Activity as ActivityIcon,
  ShieldAlert,
  Database,
  Brain,
  CheckCircle,
  AlertTriangle,
} from "lucide-react";

import { getThreats } from "../services/threatService";
import type { Threat } from "../types/threat";

interface ActivityItem {
  id: string;
  time: string;
  title: string;
  description: string;
  type: "threat" | "ioc" | "risk" | "recommendation";
  severity: string;
}

function Activity() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadActivity = async () => {
      try {
        setLoading(true);

        const data = await getThreats();

        setThreats(data);
      } catch (err) {
        console.error(err);
        setError("Unable to load security activity.");
      } finally {
        setLoading(false);
      }
    };

    loadActivity();
  }, []);

  const activities = useMemo<ActivityItem[]>(() => {
    const result: ActivityItem[] = [];

    threats.forEach((threat) => {
      const timestamp = threat.timestamp
        ? new Date(threat.timestamp).toLocaleTimeString()
        : "--:--:--";

      // Threat detection
      result.push({
        id: `${threat.id}-threat`,
        time: timestamp,
        title: "Threat detected",
        description: `${threat.attack || "Unknown attack"} detected from ${threat.source_ip}`,
        type: "threat",
        severity: threat.severity || "UNKNOWN",
      });

      // IOC lookup
      result.push({
        id: `${threat.id}-ioc`,
        time: timestamp,
        title: "IOC lookup completed",
        description: `${threat.intelligence_source || "Unknown source"} checked ${threat.source_ip}`,
        type: "ioc",
        severity: threat.severity || "UNKNOWN",
      });

      // Risk assessment
      result.push({
        id: `${threat.id}-risk`,
        time: timestamp,
        title: "Risk assessment completed",
        description: `Threat score calculated: ${threat.score}`,
        type: "risk",
        severity: threat.severity || "UNKNOWN",
      });

      // Recommendation
      result.push({
        id: `${threat.id}-recommendation`,
        time: timestamp,
        title: "Recommendation generated",
        description:
          threat.recommendation ||
          "No recommendation available.",
        type: "recommendation",
        severity: threat.severity || "UNKNOWN",
      });
    });

    return result.reverse();
  }, [threats]);

  const getActivityIcon = (type: ActivityItem["type"]) => {
    switch (type) {
      case "threat":
        return <ShieldAlert size={19} />;

      case "ioc":
        return <Database size={19} />;

      case "risk":
        return <AlertTriangle size={19} />;

      case "recommendation":
        return <Brain size={19} />;

      default:
        return <ActivityIcon size={19} />;
    }
  };

  if (loading) {
    return (
      <div className="page">
        <div className="loading-state">
          Loading security activity...
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
          <h1>Security Activity</h1>

          <p>
            Real-time Sentinel AI analysis activity
          </p>
        </div>

        <div className="activity-status">
          <span className="status-dot" />
          Agent System Active
        </div>

      </div>


      {/* ACTIVITY SUMMARY */}

      <div className="activity-summary">

        <div className="activity-summary-card">

          <ActivityIcon size={22} />

          <div>
            <span>Events Processed</span>
            <strong>{threats.length}</strong>
          </div>

        </div>


        <div className="activity-summary-card">

          <CheckCircle size={22} />

          <div>
            <span>Analysis Steps</span>
            <strong>{activities.length}</strong>
          </div>

        </div>


        <div className="activity-summary-card">

          <ShieldAlert size={22} />

          <div>
            <span>Threat Events</span>
            <strong>{threats.length}</strong>
          </div>

        </div>

      </div>


      {/* ACTIVITY TIMELINE */}

      <div className="activity-card">

        <div className="activity-card-header">

          <div>
            <h2>Agent Activity</h2>

            <p>
              Security analysis events processed by Sentinel AI
            </p>
          </div>

          <ActivityIcon size={24} />

        </div>


        <div className="activity-timeline">

          {activities.map((activity) => (

            <div
              className="activity-item"
              key={activity.id}
            >

              <div className="activity-line">

                <div
                  className={`activity-icon activity-${activity.type}`}
                >
                  {getActivityIcon(activity.type)}
                </div>

              </div>


              <div className="activity-content">

                <div className="activity-top">

                  <div>
                    <h3>{activity.title}</h3>

                    <span className="activity-time">
                      {activity.time}
                    </span>
                  </div>

                  <span
                    className={`severity-badge ${activity.severity.toLowerCase()}`}
                  >
                    {activity.severity}
                  </span>

                </div>


                <p>
                  {activity.description}
                </p>

              </div>

            </div>

          ))}

        </div>

      </div>

    </div>
  );
}

export default Activity;