import { useState } from "react";
import {
  Settings as SettingsIcon,
  Shield,
  Bell,
  Brain,
  Database,
  Save,
} from "lucide-react";

function Settings() {
  const [autoAnalysis, setAutoAnalysis] = useState(true);
  const [notifications, setNotifications] = useState(true);
  const [criticalAlerts, setCriticalAlerts] = useState(true);
  const [confidenceThreshold, setConfidenceThreshold] = useState(70);

  const handleSave = () => {
    alert("Settings saved successfully.");
  };

  return (
    <div className="page">

      <div className="page-header">
        <div>
          <h1>Settings</h1>
          <p>Configure Sentinel AI security monitoring</p>
        </div>

        <SettingsIcon size={28} />
      </div>

      {/* THREAT MONITORING */}

      <div className="settings-card">

        <div className="settings-card-header">
          <div className="settings-title">
            <Shield size={21} />

            <div>
              <h2>Threat Monitoring</h2>
              <p>Configure automated threat analysis</p>
            </div>
          </div>
        </div>

        <div className="settings-row">

          <div>
            <strong>Automatic Threat Analysis</strong>

            <p>
              Automatically analyze incoming security events
            </p>
          </div>

          <label className="toggle">

            <input
              type="checkbox"
              checked={autoAnalysis}
              onChange={(e) =>
                setAutoAnalysis(e.target.checked)
              }
            />

            <span className="toggle-slider" />

          </label>

        </div>

        <div className="settings-row">

          <div>
            <strong>Critical Threat Detection</strong>

            <p>
              Immediately flag threats with critical severity
            </p>
          </div>

          <label className="toggle">

            <input
              type="checkbox"
              checked={criticalAlerts}
              onChange={(e) =>
                setCriticalAlerts(e.target.checked)
              }
            />

            <span className="toggle-slider" />

          </label>

        </div>

      </div>


      {/* AI ANALYSIS */}

      <div className="settings-card">

        <div className="settings-card-header">

          <div className="settings-title">

            <Brain size={21} />

            <div>
              <h2>AI Analysis</h2>

              <p>
                Configure Sentinel AI analysis behavior
              </p>
            </div>

          </div>

        </div>

        <div className="settings-row settings-column">

          <div>
            <strong>Confidence Threshold</strong>

            <p>
              Minimum confidence required for an AI threat assessment
            </p>
          </div>

          <div className="range-container">

            <input
              type="range"
              min="0"
              max="100"
              value={confidenceThreshold}
              onChange={(e) =>
                setConfidenceThreshold(
                  Number(e.target.value)
                )
              }
            />

            <span>
              {confidenceThreshold}%
            </span>

          </div>

        </div>

      </div>


      {/* NOTIFICATIONS */}

      <div className="settings-card">

        <div className="settings-card-header">

          <div className="settings-title">

            <Bell size={21} />

            <div>
              <h2>Notifications</h2>

              <p>
                Configure security notifications
              </p>
            </div>

          </div>

        </div>

        <div className="settings-row">

          <div>
            <strong>Security Notifications</strong>

            <p>
              Receive notifications for security events
            </p>
          </div>

          <label className="toggle">

            <input
              type="checkbox"
              checked={notifications}
              onChange={(e) =>
                setNotifications(e.target.checked)
              }
            />

            <span className="toggle-slider" />

          </label>

        </div>

      </div>


      {/* THREAT INTELLIGENCE */}

      <div className="settings-card">

        <div className="settings-card-header">

          <div className="settings-title">

            <Database size={21} />

            <div>
              <h2>Threat Intelligence</h2>

              <p>
                Configure intelligence sources
              </p>
            </div>

          </div>

        </div>

        <div className="intelligence-source">

          <div>
            <strong>Local IOC Dataset</strong>

            <p>
              Local malicious IP intelligence database
            </p>
          </div>

          <span className="source-status">
            Active
          </span>

        </div>

        <div className="intelligence-source">

          <div>
            <strong>AbuseIPDB</strong>

            <p>
              External IP reputation intelligence
            </p>
          </div>

          <span className="source-status">
            Active
          </span>

        </div>

      </div>


      {/* SAVE */}

      <div className="settings-actions">

        <button
          className="save-settings-button"
          onClick={handleSave}
        >
          <Save size={18} />
          Save Settings
        </button>

      </div>

    </div>
  );
}

export default Settings;