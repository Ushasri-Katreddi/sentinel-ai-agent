import type { Threat } from "../../types/threat";
import {
  Activity,
  AlertTriangle,
  ShieldAlert,
  Globe,
} from "lucide-react";

interface ThreatSummaryProps {
  threats: Threat[];
}

function ThreatSummary({ threats }: ThreatSummaryProps) {
  // Total number of analyzed threats
  const totalThreats = threats.length;

  // Number of critical threats
  const criticalThreats = threats.filter(
    (threat) => threat.severity.toUpperCase() === "CRITICAL"
  ).length;

  // Number of threats involving malicious IPs
  const maliciousIPs = threats.filter(
    (threat) => threat.malicious_ip === true
  ).length;

  // Average threat score
  const averageScore =
    threats.length > 0
      ? Math.round(
          threats.reduce((total, threat) => total + threat.score, 0) /
            threats.length
        )
      : 0;

  const metrics = [
    {
      title: "Total Threats",
      value: totalThreats,
      description: "Analyses performed",
      icon: Activity,
    },
    {
      title: "Critical Threats",
      value: criticalThreats,
      description: "Immediate attention",
      icon: AlertTriangle,
    },
    {
      title: "Malicious IPs",
      value: maliciousIPs,
      description: "IOC detections",
      icon: ShieldAlert,
    },
    {
      title: "Average Score",
      value: averageScore,
      description: "Overall threat score",
      icon: Globe,
    },
  ];

  return (
    <div className="summary-grid">
      {metrics.map((metric) => {
        const Icon = metric.icon;

        return (
          <div className="summary-card" key={metric.title}>
            <div className="summary-card-content">
              <p>{metric.title}</p>
              <h3>{metric.value}</h3>
              <span>{metric.description}</span>
            </div>

            <div className="summary-icon">
              <Icon size={26} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default ThreatSummary;