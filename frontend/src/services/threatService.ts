import axios from "axios";

const API_URL = "http://127.0.0.1:8000";

export interface AnalyzeLogRequest {
  timestamp: string;
  source_ip: string;
  destination_ip: string | null;
  username: string | null;
  event: string | null;
  failed_attempts: number | null;
  country: string | null;
  device: string | null;
}

export const getThreats = async () => {
  const response = await axios.get(`${API_URL}/threats`);

  return response.data;
};

export const analyzeThreat = async (
  log: AnalyzeLogRequest
) => {
  const response = await axios.post(
    `${API_URL}/analyze-log`,
    log
  );

  return response.data;
};