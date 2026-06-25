import type {
  DevicesResponse,
  ExplainResponse,
  IncidentsResponse,
  PacketsResponse,
  QuarantineResponse,
  StatsResponse,
  IncidentReport,
} from "../types";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000";

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    cache: "no-store",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });

  if (!response.ok) {
    throw new Error(`Request failed: ${response.status} ${response.statusText}`);
  }

  return response.json() as Promise<T>;
}

export function getDevices() {
  return requestJson<DevicesResponse>("/api/devices");
}

export function getPackets() {
  return requestJson<PacketsResponse>("/api/packets");
}

export function getQuarantineLog() {
  return requestJson<QuarantineResponse>("/api/quarantine");
}

export function getIncidents() {
  return requestJson<IncidentsResponse>("/api/incidents");
}

export function postIncident(incident: Omit<IncidentReport, "raw" | "path">) {
  return requestJson<{ status: string; id: string }>("/api/incidents", {
    method: "POST",
    body: JSON.stringify(incident),
  });
}

export function getStats() {
  return requestJson<StatsResponse>("/api/stats");
}

export function explainThreat(ip: string) {
  return requestJson<ExplainResponse>(`/api/ai/explain/${encodeURIComponent(ip)}`);
}

export function quarantineDevice(ip: string) {
  return requestJson<{ result: any; device: any; timestamp: string }>(`/api/quarantine/${encodeURIComponent(ip)}`, {
    method: "POST",
  });
}
