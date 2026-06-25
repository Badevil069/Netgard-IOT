"use client";

import { AlertTriangle } from "lucide-react";
import type { Device } from "../types";

export function ThreatAlert({ devices }: { devices: Device[] }) {
  const rogue = devices.find((device) => device.status === "ROGUE");
  if (!rogue) return null;

  return (
    <section className="animate-pulseBorder rounded-lg border border-red bg-red/15 px-4 py-3.5 text-red shadow-rogue">
      <div className="flex items-center gap-3">
        <AlertTriangle size={18} className="shrink-0 animate-bounce" />
        <span className="text-xs sm:text-sm font-bold tracking-wide font-mono">
          🚨 CRITICAL: Rogue device {rogue.ip} detected — {rogue.unique_ports} ports scanned | Auto-quarantine active
        </span>
      </div>
    </section>
  );
}
