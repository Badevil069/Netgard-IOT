"use client";

import { useEffect, useRef } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "./ui";
import type { Device, Packet } from "../types";

export function PacketFeed({ packets, devices }: { packets: Packet[]; devices: Device[] }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const rogueIps = new Set(devices.filter((device) => device.status === "ROGUE").map((device) => device.ip));

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [packets]);

  const formatTime = (ts: string) => {
    try {
      const date = new Date(ts);
      return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
    } catch {
      return "00:00:00";
    }
  };

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <CardTitle>Live Packet Feed</CardTitle>
        <span className="font-mono text-xs text-text-secondary">{packets.length} rows</span>
      </CardHeader>
      <CardContent>
        <div
          ref={containerRef}
          className="h-[320px] overflow-y-auto rounded-md border border-black bg-black/95 p-4 font-mono text-xs leading-6 scrollbar-thin"
        >
          {packets.slice(-30).map((packet, index) => {
            const rogue = rogueIps.has(packet.src_ip);
            const timeStr = formatTime(packet.timestamp);
            return (
              <div
                key={`${packet.timestamp}-${packet.src_ip}-${packet.dst_ip}-${index}`}
                className={rogue ? "text-[#ff4444] font-bold" : "text-[#00ff88]/90"}
              >
                <span className="text-slate-500">[{timeStr}]</span> {packet.src_ip}:{packet.src_port} → {packet.dst_ip}:{packet.dst_port} {packet.protocol} {packet.packet_size}B {rogue ? "🔴" : "✅"}
              </div>
            );
          })}
          {!packets.length && <div className="text-text-secondary">Sniffing live network interfaces...</div>}
        </div>
      </CardContent>
    </Card>
  );
}
