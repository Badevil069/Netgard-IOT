"use client";

import { Cpu, LockKeyhole, ShieldCheck, Siren } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { AIThreatCard } from "../components/AIThreatCard";
import { CiscoTerminal } from "../components/CiscoTerminal";
import { DeviceTable } from "../components/DeviceTable";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { EventTimeline } from "../components/EventTimeline";
import { Header } from "../components/Header";
import { MetricCard } from "../components/MetricCard";
import { NetworkTopology } from "../components/NetworkTopology";
import { PacketFeed } from "../components/PacketFeed";
import { QuarantineLog } from "../components/QuarantineLog";
import { ThreatAlert } from "../components/ThreatAlert";
import { TrafficGraph } from "../components/TrafficGraph";
import { useDevices } from "../hooks/useDevices";
import { usePackets } from "../hooks/usePackets";
import { useQuarantine } from "../hooks/useQuarantine";
import { useTrafficHistory } from "../hooks/useTrafficHistory";
import { quarantineDevice, getIncidents, postIncident } from "../lib/api";
import type { SummaryStats, TimelineEvent, IncidentReport } from "../types";

export default function DashboardPage() {
  const { devices, loading: devicesLoading } = useDevices();
  const { packets, totalPackets } = usePackets();
  const { actions } = useQuarantine();
  const { history } = useTrafficHistory(devices);
  
  const [busyIp, setBusyIp] = useState<string | null>(null);
  const [incidents, setIncidents] = useState<IncidentReport[]>([]);
  const [reportedIncidentIps, setReportedIncidentIps] = useState<string[]>([]);
  const [activeIncident, setActiveIncident] = useState<IncidentReport | null>(null);

  
  useEffect(() => {
    let mounted = true;
    const fetchIncidents = async () => {
      try {
        const res = await getIncidents();
        if (mounted) {
          setIncidents(res.incidents);
        }
      } catch (err) {
        console.error("Failed to load incidents", err);
      }
    };
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 2000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  
  useEffect(() => {
    const rogueDevice = devices.find((device) => device.status === "ROGUE");
    if (rogueDevice && !reportedIncidentIps.includes(rogueDevice.ip)) {
      const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, "");
      const randomId = Math.floor(1000 + Math.random() * 9000);
      const incidentId = `INC-${dateStr}-${randomId}`;

      const newIncident: Omit<IncidentReport, "raw" | "path"> = {
        id: incidentId,
        device: rogueDevice.ip,
        threat: "Rogue Device Detected",
        type: rogueDevice.detection_reasons.join("; ") || "Abnormal packet rate/ports scan",
        affected: "VLAN 999 Isolation Segment",
        action: "Auto-quarantine response engaged",
        timestamp: new Date().toISOString(),
      };

      
      setReportedIncidentIps((prev) => [...prev, rogueDevice.ip]);
      
      const saveIncident = async () => {
        try {
          await postIncident(newIncident);
          
          setActiveIncident({
            ...newIncident,
            raw: "",
            path: `${incidentId}.txt`,
          });
          
          const res = await getIncidents();
          setIncidents(res.incidents);
        } catch (err) {
          console.error("Failed to save incident report", err);
        }
      };

      saveIncident();
    }
  }, [devices, reportedIncidentIps]);

  
  const stats: SummaryStats = useMemo(() => {
    const rogue = devices.filter((device) => device.status === "ROGUE").length;
    const quarantined = devices.filter((device) => device.status === "QUARANTINED" || device.quarantined).length;
    return {
      total_devices: devices.length,
      normal_devices: Math.max(0, devices.length - rogue - quarantined),
      rogue_devices: rogue,
      quarantined_devices: quarantined,
      total_packets: totalPackets,
      incident_count: incidents.length,
      threat_level: rogue > 0 ? "RED" : quarantined > 0 ? "YELLOW" : "GREEN",
      system_status: "ONLINE",
      timestamp: new Date().toISOString(),
    };
  }, [devices, totalPackets, incidents.length]);

  const rogueDevices = devices.filter((device) => device.status === "ROGUE");
  const primaryTarget = rogueDevices[0] ?? devices.find((device) => device.status === "QUARANTINED");

  
  const events: TimelineEvent[] = useMemo(() => {
    const deviceEvents = devices.map((device) => {
      let type: "device" | "warning" | "rogue" | "quarantine" | "contained" = "device";
      let title = "Device discovered";
      let description = `${device.ip} discovered on network`;

      if (device.status === "ROGUE") {
        type = "rogue";
        title = "Rogue classified";
        description = `${device.ip} classified as rogue threat`;
      } else if (device.status === "QUARANTINED") {
        type = "contained";
        title = "Threat contained";
        description = `${device.ip} successfully isolated`;
      } else if (device.unique_ports > 10 || device.pps > 5) {
        type = "warning";
        title = "Suspicious activity";
        description = `${device.ip} warning: ${device.pps.toFixed(1)} pps, ${device.unique_ports} ports`;
      }

      return {
        id: `device-${device.ip}-${device.last_seen}`,
        timestamp: device.last_seen,
        type,
        title,
        description,
        ip: device.ip,
      };
    }) satisfies TimelineEvent[];

    const quarantineEvents = actions.map((action, index) => ({
      id: `quarantine-${action.ip}-${action.timestamp}-${index}`,
      timestamp: action.timestamp,
      type: "quarantine" as const,
      title: "Quarantine started",
      description: `VLAN 999 switch isolation triggered for ${action.ip}`,
      ip: action.ip,
    })) satisfies TimelineEvent[];

    return [...deviceEvents, ...quarantineEvents].sort(
      (a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)
    );
  }, [actions, devices]);

  const handleQuarantine = async (ip: string) => {
    setBusyIp(ip);
    try {
      await quarantineDevice(ip);
    } catch (err) {
      console.error("Quarantine command error", err);
    } finally {
      setBusyIp(null);
    }
  };

  return (
    <div className="dashboard-shell min-h-screen bg-bg text-text-primary pb-10">
      {}
      <Header stats={stats} />

      <div className="grid-overlay">
        <main className="mx-auto w-full max-w-[1800px] space-y-5 px-4 py-4 md:px-6">
          {}
          {activeIncident && (
            <div className="animate-pulseBorder rounded-lg border border-red bg-red/10 p-4 text-red flex flex-col md:flex-row items-center justify-between gap-4 shadow-rogue">
              <div className="flex items-center gap-3">
                <span className="text-xl">🚨</span>
                <span className="text-xs sm:text-sm font-bold font-mono">
                  INCIDENT DETECTED: {activeIncident.id} | Rogue device {activeIncident.device} isolation active | Auto-quarantine active
                </span>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => window.print()}
                  className="rounded border border-red bg-red/20 hover:bg-red/30 px-3 py-1 text-xs font-mono font-bold text-red transition-all"
                >
                  Export PDF
                </button>
                <button
                  onClick={() => setActiveIncident(null)}
                  className="text-red/80 hover:text-red px-2 text-sm font-bold font-mono"
                >
                  ✕
                </button>
              </div>
            </div>
          )}

          {}
          <ErrorBoundary>
            <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard 
                title="Total Devices" 
                value={stats.total_devices} 
                icon={Cpu} 
                tone="cyan" 
                detail={`${stats.total_packets} packets captures`} 
              />
              <MetricCard 
                title="Normal Devices" 
                value={stats.normal_devices} 
                icon={ShieldCheck} 
                tone="green" 
                detail="trusted behavior profiles" 
              />
              <MetricCard 
                title="Threats Detected" 
                value={stats.rogue_devices} 
                icon={Siren} 
                tone="red" 
                pulse={stats.rogue_devices > 0} 
                detail={rogueDevices[0] ? `Rogue: ${rogueDevices[0].ip}` : "no rogue detected"} 
              />
              <MetricCard 
                title="Quarantined" 
                value={stats.quarantined_devices} 
                icon={LockKeyhole} 
                tone="purple" 
                detail={`${actions.length} commands logged`} 
              />
            </section>
          </ErrorBoundary>

          {}
          <ThreatAlert devices={devices} />

          {}
          <section className="grid gap-4 lg:grid-cols-5">
            <div className="lg:col-span-3">
              <ErrorBoundary>
                <DeviceTable 
                  devices={devices} 
                  loading={devicesLoading} 
                  onQuarantine={handleQuarantine} 
                  busyIp={busyIp} 
                />
              </ErrorBoundary>
            </div>
            <div className="lg:col-span-2">
              <ErrorBoundary>
                <NetworkTopology devices={devices} />
              </ErrorBoundary>
            </div>
          </section>

          {}
          <ErrorBoundary>
            <TrafficGraph devices={devices} history={history} />
          </ErrorBoundary>

          {}
          <section className="grid gap-4 lg:grid-cols-5">
            <div className="lg:col-span-3">
              <ErrorBoundary>
                <PacketFeed packets={packets} devices={devices} />
              </ErrorBoundary>
            </div>
            <div className="lg:col-span-2">
              <ErrorBoundary>
                <EventTimeline events={events} />
              </ErrorBoundary>
            </div>
          </section>

          {}
          {rogueDevices.length > 0 && (
            <section className="grid gap-4">
              {rogueDevices.map((device) => (
                <ErrorBoundary key={device.ip}>
                  <AIThreatCard 
                    device={device} 
                    onQuarantine={handleQuarantine} 
                    busy={busyIp === device.ip} 
                  />
                </ErrorBoundary>
              ))}
            </section>
          )}

          {}
          <ErrorBoundary>
            <CiscoTerminal 
              target={primaryTarget} 
              onExecute={handleQuarantine} 
              busy={busyIp === primaryTarget?.ip} 
            />
          </ErrorBoundary>

          {}
          <ErrorBoundary>
            <QuarantineLog actions={actions} />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
