export interface Threat {
  id: number;
  timestamp: string;
  source_ip: string;
  destination_ip: string | null;
  username: string | null;
  event: string | null;
  failed_attempts: number | null;
  country: string | null;
  device: string | null;

  score: number;
  severity: string;
  attack: string;
  confidence: number;
  recommendation: string;

  score_breakdown: Record<string, number> | null;

  malicious_ip: boolean;
  abuse_score: number | null;
  ioc_country: string | null;
  isp: string | null;
  intelligence_source: string | null;
}