import {
  X,
  ShieldAlert,
  Globe,
  Server,
  Database,
  AlertTriangle,
} from "lucide-react";

import type { Threat } from "../../types/threat";

interface ThreatDetailsProps {
  threat: Threat;
  onClose: () => void;
}

function ThreatDetails({ threat, onClose }: ThreatDetailsProps) {
  return (
    <div className="threat-drawer-overlay">

      <div className="threat-drawer">

        {/* HEADER */}
        <div className="drawer-header">

          <div>
            <h2>Threat Details</h2>
            <p>Sentinel AI threat analysis</p>
          </div>

          <button
            className="drawer-close"
            onClick={onClose}
          >
            <X size={22} />
          </button>

        </div>


        {/* THREAT OVERVIEW */}
        <div className="drawer-section">

          <div className="threat-overview">

            <ShieldAlert size={32} />

            <div>
              <span
                className={`severity-badge ${threat.severity?.toLowerCase()}`}
              >
                {threat.severity}
              </span>

              <h3>{threat.attack || "Unknown Attack"}</h3>
            </div>

          </div>

        </div>


        {/* SCORE */}
        <div className="drawer-section">

          <div className="section-title">
            <AlertTriangle size={18} />
            Threat Assessment
          </div>

          <div className="assessment-grid">

            <div className="assessment-card">
              <span>Threat Score</span>
              <strong>{threat.score}</strong>
            </div>

            <div className="assessment-card">
              <span>Confidence</span>
              <strong>
  {threat.confidence <= 1
    ? `${Math.round(threat.confidence * 100)}%`
    : `${threat.confidence}%`}
</strong>
            </div>

          </div>

        </div>


        {/* SOURCE INFORMATION */}
        <div className="drawer-section">

          <div className="section-title">
            <Globe size={18} />
            Source Information
          </div>

          <div className="detail-grid">

            <div className="detail-item">
              <span>Source IP</span>
              <strong>{threat.source_ip}</strong>
            </div>

            <div className="detail-item">
              <span>Destination IP</span>
              <strong>{threat.destination_ip || "Unknown"}</strong>
            </div>

            <div className="detail-item">
              <span>Country</span>
              <strong>
                {threat.ioc_country || threat.country || "Unknown"}
              </strong>
            </div>

            <div className="detail-item">
              <span>ISP</span>
              <strong>{threat.isp || "Unknown"}</strong>
            </div>

          </div>

        </div>


        {/* EVENT INFORMATION */}
        <div className="drawer-section">

          <div className="section-title">
            <Server size={18} />
            Event Information
          </div>

          <div className="detail-grid">

            <div className="detail-item">
              <span>Username</span>
              <strong>
                {threat.username || "Unknown"}
              </strong>
            </div>

            <div className="detail-item">
              <span>Device</span>
              <strong>
                {threat.device || "Unknown"}
              </strong>
            </div>

            <div className="detail-item">
              <span>Failed Attempts</span>
              <strong>
                {threat.failed_attempts ?? 0}
              </strong>
            </div>

            <div className="detail-item">
              <span>Event</span>
              <strong>
                {threat.event || "Unknown"}
              </strong>
            </div>

          </div>

        </div>


        {/* IOC */}
        <div className="drawer-section">

          <div className="section-title">
            <Database size={18} />
            IOC Intelligence
          </div>

          <div className="detail-grid">

            <div className="detail-item">
              <span>Malicious IP</span>

              <strong
                className={
                  threat.malicious_ip
                    ? "malicious-yes"
                    : "malicious-no"
                }
              >
                {threat.malicious_ip ? "YES" : "NO"}
              </strong>

            </div>

            <div className="detail-item">
              <span>Abuse Score</span>
              <strong>
                {threat.abuse_score ?? "N/A"}
              </strong>
            </div>

            <div className="detail-item">
              <span>Intelligence Source</span>
              <strong>
                {threat.intelligence_source || "Unknown"}
              </strong>
            </div>

            <div className="detail-item">
              <span>IOC Country</span>
              <strong>
                {threat.ioc_country || "Unknown"}
              </strong>
            </div>

          </div>

        </div>


        {/* SCORE BREAKDOWN */}
        {threat.score_breakdown && (
          <div className="drawer-section">

            <div className="section-title">
              <AlertTriangle size={18} />
              Score Breakdown
            </div>

            <div className="score-breakdown">

              {Object.entries(threat.score_breakdown).map(
                ([key, value]) => (

                  <div
                    className="score-row"
                    key={key}
                  >

                    <span>
                      {key.replaceAll("_", " ")}
                    </span>

                    <strong>
                      {value}
                    </strong>

                  </div>

                )
              )}

            </div>

          </div>
        )}


        {/* RECOMMENDATION */}
        <div className="drawer-section recommendation-section">

          <div className="section-title">
            <ShieldAlert size={18} />
            AI Recommendation
          </div>

          <div className="recommendation-box">

            {threat.recommendation ||
              "No recommendation available."}

          </div>

        </div>


      </div>

    </div>
  );
}

export default ThreatDetails;