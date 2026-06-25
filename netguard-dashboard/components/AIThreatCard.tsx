"use client";

import { Loader2 } from "lucide-react";
import { useEffect, useState } from "react";

import { explainThreat } from "../lib/api";
import type { Device } from "../types";
import { Button, Card, CardContent, CardHeader, CardTitle } from "./ui";

export function AIThreatCard({ device, onQuarantine, busy }: { device: Device; onQuarantine: (ip: string) => void; busy?: boolean }) {
  const [explanation, setExplanation] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    explainThreat(device.ip)
      .then((response) => {
        if (mounted) setExplanation(response.explanation);
      })
      .catch(() => {
        if (mounted) setExplanation("AI explanation is currently unavailable. LLaMA 3 endpoint failed to reply. Please quarantine this IP address immediately to isolate threat.");
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [device.ip]);

  
  const evidence: string[] = [];
  if (device.unique_ports > 50) {
    evidence.push(`Port scan: ${device.unique_ports} unique ports (threshold: 50)`);
  } else if (device.unique_ports > 10) {
    evidence.push(`Elevated port scan: ${device.unique_ports} unique ports`);
  }

  if (device.pps > 5) {
    evidence.push(`Rate anomaly: ${device.pps.toFixed(2)} pps (threshold: 5)`);
  }

  if (device.name === "UNKNOWN") {
    evidence.push("Unknown MAC vendor");
  }

  if (device.raw_score !== undefined && device.raw_score < 0) {
    evidence.push(`ML anomaly score: ${device.raw_score.toFixed(2)}`);
  } else if (device.raw_score !== undefined) {
    evidence.push(`ML score: ${device.raw_score.toFixed(2)}`);
  }

  return (
    <Card className="border border-red bg-red/5 p-1.5 shadow-rogue">
      <CardHeader className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-red/20">
        <div>
          <CardTitle className="text-red font-bold text-sm">⚠️ THREAT REPORT — {device.ip}</CardTitle>
          <p className="mt-1 text-xs text-text-secondary">{device.name} | MAC: {device.mac}</p>
        </div>
        <span className="rounded-full border border-red/60 bg-red/10 px-3 py-1 text-[11px] font-extrabold uppercase tracking-[0.14em] text-red animate-pulse">
          CRITICAL
        </span>
      </CardHeader>
      <CardContent className="space-y-4 pt-4">
        {}
        <div className="space-y-2">
          <p className="text-[10px] uppercase tracking-[0.14em] text-text-secondary font-bold">Detection Evidence</p>
          <ul className="space-y-1.5 pl-1">
            {evidence.map((item, idx) => (
              <li key={idx} className="flex items-center gap-2 text-xs font-mono text-text-primary">
                <span className="text-green text-xs font-sans">✅</span> {item}
              </li>
            ))}
            {evidence.length === 0 && (
              <li className="flex items-center gap-2 text-xs font-mono text-text-secondary">
                <span className="text-orange text-xs font-sans">⚠️</span> ML anomaly score warning: anomalous packet length signature
              </li>
            )}
          </ul>
        </div>

        {}
        <div className="rounded border border-red/20 bg-black/40 px-3 py-2 font-mono text-xs text-cyan">
          confidence = anomaly score + rule override + evidence weight = {device.confidence.toFixed(1)}%
        </div>

        {}
        <div className="space-y-2">
          <p className="text-[10px] uppercase tracking-[0.14em] text-text-secondary font-bold">LLaMA 3 Threat Explanation</p>
          <div className="rounded-md border border-border bg-[#0a0e1a]/80 p-4 text-xs font-mono leading-6 text-text-secondary min-h-[90px] max-h-[220px] overflow-y-auto scrollbar-thin">
            {loading ? (
              <span className="inline-flex items-center gap-2 text-cyan">
                <Loader2 className="animate-spin" size={13} /> Fetching LLaMA 3 threat intelligence...
              </span>
            ) : (
              explanation
            )}
          </div>
        </div>

        {}
        <div className="flex flex-wrap gap-2 pt-2">
          <Button 
            className="border-red bg-red/10 text-red hover:bg-red/20 font-bold" 
            onClick={() => onQuarantine(device.ip)} 
            disabled={busy || device.status === "QUARANTINED"}
          >
            {busy ? <Loader2 className="animate-spin mr-1" size={13} /> : <span className="mr-1">🔴</span>}
            Quarantine Now
          </Button>
          <Button className="border-cyan/40 text-cyan hover:bg-cyan/5">
            <span className="mr-1">📧</span> Send Alert
          </Button>
          <Button className="border-slate-600 text-slate-200 hover:bg-slate-800" onClick={() => window.print()}>
            <span className="mr-1">📋</span> Export Report
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
