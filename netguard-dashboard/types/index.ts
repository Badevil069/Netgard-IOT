export type DeviceStatus = "NORMAL" | "ROGUE" | "QUARANTINED";

export interface Device {
  name: string;
  ip: string;
  mac: string;
  status: DeviceStatus;
  pps: number;
  unique_ports: number;
  avg_packet_size: number;
  confidence: number;
  quarantined: boolean;
  last_seen: string;
  detection_reasons: string[];
  raw_score?: number;
}

export interface Packet {
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  packet_size: number;
}

export interface QuarantineAction {
  ip: string;
  mac: string;
  timestamp: string;
  vlan: number;
  success: boolean;
  commands?: string[];
  commands_sent?: string[];
  action?: string;
  note?: string;
}

export interface IncidentReport {
  id: string;
  device: string;
  threat: string;
  type: string;
  affected: string;
  action: string;
  timestamp: string;
  raw: string;
  path: string;
}

export interface SummaryStats {
  total_devices: number;
  normal_devices: number;
  rogue_devices: number;
  quarantined_devices: number;
  total_packets: number;
  incident_count: number;
  threat_level: "GREEN" | "YELLOW" | "RED";
  system_status: string;
  timestamp: string;
}

export interface DevicesResponse {
  devices: Device[];
  timestamp: string;
}

export interface PacketsResponse {
  packets: Packet[];
  total_packets?: number;
  timestamp: string;
}

export interface QuarantineResponse {
  actions: QuarantineAction[];
  timestamp: string;
}

export interface IncidentsResponse {
  incidents: IncidentReport[];
  timestamp: string;
}

export interface StatsResponse {
  stats: SummaryStats;
  timestamp: string;
}

export interface ExplainResponse {
  ip: string;
  explanation: string;
  device: Device;
  timestamp: string;
}

export interface TrafficPoint {
  timestamp: string;
  value: number;
}

export interface TrafficHistory {
  [ip: string]: TrafficPoint[];
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  type: "device" | "warning" | "rogue" | "quarantine" | "contained";
  title: string;
  description: string;
  ip?: string;
}
