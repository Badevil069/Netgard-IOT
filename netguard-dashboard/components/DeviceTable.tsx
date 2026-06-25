"use client";

import { AlertTriangle, CheckCircle2, Loader2, LockKeyhole, Search } from "lucide-react";

import { Button, Card, CardContent, CardHeader, CardTitle, Skeleton } from "./ui";
import { cn } from "../lib/utils";
import type { Device } from "../types";

type DeviceTableProps = {
  devices: Device[];
  loading: boolean;
  onQuarantine: (ip: string) => void;
  busyIp?: string | null;
};

function statusClass(status: Device["status"]) {
  if (status === "ROGUE") return "border-red bg-red/10 text-red animate-pulse";
  if (status === "QUARANTINED") return "border-purple bg-purple/10 text-purple";
  return "border-green bg-green/10 text-green";
}

export function DeviceTable({ devices, loading, onQuarantine, busyIp }: DeviceTableProps) {
  const orderedDevices = [...devices].sort((a, b) => {
    const priority = { ROGUE: 0, QUARANTINED: 1, NORMAL: 2 };
    return priority[a.status] - priority[b.status] || b.unique_ports - a.unique_ports;
  });

  return (
    <Card className="overflow-hidden border border-border">
      <CardHeader className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <CardTitle>Device Inventory</CardTitle>
          <p className="mt-1 text-xs text-text-secondary">Sorted by active risk, then scan breadth.</p>
        </div>
        <div className="flex items-center gap-2 rounded-md border border-border bg-bg/70 px-3 py-2 text-xs text-text-secondary">
          <Search size={14} />
          {orderedDevices.length} observed endpoints
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {loading ? (
          <div className="p-4 space-y-4">
            <div className="flex space-x-4">
              <Skeleton className="h-5 w-1/4" />
              <Skeleton className="h-5 w-1/4" />
              <Skeleton className="h-5 w-1/4" />
              <Skeleton className="h-5 w-1/4" />
            </div>
            <div className="h-[1px] bg-white/5" />
            {[0, 1, 2, 3].map((item) => (
              <div key={item} className="flex items-center space-x-4 py-2">
                <Skeleton className="h-9 w-9 rounded-md" />
                <div className="space-y-2 flex-1">
                  <Skeleton className="h-4 w-[30%]" />
                  <Skeleton className="h-3 w-[20%]" />
                </div>
                <Skeleton className="h-4 w-[10%]" />
                <Skeleton className="h-4 w-[8%]" />
                <Skeleton className="h-4 w-[12%]" />
                <Skeleton className="h-7 w-[15%]" />
              </div>
            ))}
          </div>
        ) : (
          <div className="max-h-[520px] overflow-auto scrollbar-thin">
            <table className="min-w-[980px] w-full text-left text-sm">
              <thead className="sticky top-0 z-10 border-b border-border bg-card text-[11px] uppercase tracking-[0.14em] text-text-secondary">
                <tr>
                  <th className="px-4 py-3">Device</th>
                  <th className="px-4 py-3">IP</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">PPS</th>
                  <th className="px-4 py-3">Ports</th>
                  <th className="px-4 py-3">Confidence</th>
                  <th className="px-4 py-3">Reasons</th>
                  <th className="px-4 py-3">Action</th>
                </tr>
              </thead>
              <tbody>
                {orderedDevices.map((device) => (
                  <tr
                    key={device.ip}
                    className={cn(
                      "border-b border-white/5 transition-all duration-300 hover:bg-white/[0.025]",
                      device.status === "ROGUE" && "bg-red/5 border-l-2 border-red-500 shadow-rogue",
                      device.status === "QUARANTINED" && "bg-purple/5",
                    )}
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <span className={cn("grid size-8 place-items-center rounded-md border transition-all duration-300", device.status === "ROGUE" ? "border-red/50 bg-red/10 text-red" : device.status === "QUARANTINED" ? "border-purple/50 bg-purple/10 text-purple" : "border-green/40 bg-green/10 text-green")}>
                          {device.status === "ROGUE" ? <AlertTriangle size={15} /> : <CheckCircle2 size={15} />}
                        </span>
                        <div>
                          <p className="font-medium text-text-primary transition-all duration-300">{device.name}</p>
                          <p className="font-mono text-[11px] text-text-secondary">{device.mac}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-cyan">{device.ip}</td>
                    <td className="px-4 py-3">
                      <span className={cn("rounded-full border px-2.5 py-1 text-[10px] font-bold tracking-[0.12em]", statusClass(device.status))}>
                        {device.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono transition-all duration-300">{device.pps.toFixed(2)}</td>
                    <td className="px-4 py-3 font-mono transition-all duration-300">{device.unique_ports}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-20 rounded bg-slate-800">
                          <div
                            className={cn("h-2 rounded transition-all duration-300", device.status === "ROGUE" ? "bg-red" : "bg-green")}
                            style={{ width: `${Math.min(100, Math.max(0, device.confidence))}%` }}
                          />
                        </div>
                        <span className="font-mono text-xs text-text-secondary transition-all duration-300">{device.confidence.toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="max-w-[300px] px-4 py-3 text-xs text-text-secondary">
                      <span className="block max-h-9 overflow-hidden transition-all duration-300">{device.detection_reasons.length ? device.detection_reasons.slice(0, 2).join("; ") : "Baseline behavior"}</span>
                    </td>
                    <td className="px-4 py-3">
                      {device.status === "ROGUE" ? (
                        <Button className="border-red/60 bg-red/10 text-red hover:bg-red/20" onClick={() => onQuarantine(device.ip)} disabled={busyIp === device.ip}>
                          {busyIp === device.ip ? <Loader2 className="animate-spin" size={15} /> : <LockKeyhole size={15} />}
                          Quarantine
                        </Button>
                      ) : device.status === "QUARANTINED" ? (
                        <span className="text-xs font-semibold uppercase tracking-[0.16em] text-purple flex items-center gap-1">Contained ✅</span>
                      ) : (
                        <span className="text-xs text-text-secondary">Monitoring</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
