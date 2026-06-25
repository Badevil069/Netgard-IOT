"use client";

import { Loader2, Play } from "lucide-react";
import { useEffect, useState } from "react";

import { Button, Card, CardContent, CardHeader, CardTitle } from "./ui";
import type { Device } from "../types";

const baseCommands = [
  "switch# enable",
  "switch# configure terminal",
  "switch(config)# interface GigabitEthernet0/1",
  "switch(config-if)# switchport access vlan 999",
  "switch(config-if)# shutdown",
];

export function CiscoTerminal({ target, onExecute, busy }: { target?: Device; onExecute: (ip: string) => void; busy?: boolean }) {
  const [terminalLines, setTerminalLines] = useState<string[]>([]);

  const targetIp = target?.ip;

  useEffect(() => {
    // Clear and start typing animation whenever target changes
    setTerminalLines([]);
    if (!targetIp) return;

    let commandIdx = 0;
    let charIdx = 0;
    let currentLine = "";
    let interval: NodeJS.Timeout;

    const typeChar = () => {
      if (commandIdx >= baseCommands.length) {
        clearInterval(interval);
        return;
      }

      const fullCmd = baseCommands[commandIdx];
      if (charIdx < fullCmd.length) {
        currentLine += fullCmd[charIdx];
        charIdx++;
        setTerminalLines((prev) => {
          const next = [...prev];
          if (next.length <= commandIdx) {
            return [...next, currentLine];
          } else {
            next[commandIdx] = currentLine;
            return next;
          }
        });
      } else {
        commandIdx++;
        charIdx = 0;
        currentLine = "";
      }
    };

    interval = setInterval(typeChar, 30); // 30ms per character typing rate
    return () => clearInterval(interval);
  }, [targetIp]);

  return (
    <Card className="h-full border border-border">
      <CardHeader className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-white/5">
        <div>
          <CardTitle>NetGuard Auto-Response Engine</CardTitle>
          <p className="mt-1 font-mono text-xs text-text-secondary">
            {target ? `IP: ${target.ip} | MAC: ${target.mac}` : "No active target"}
          </p>
        </div>
        <span className="rounded-md border border-orange/40 bg-orange/10 px-2 py-1 font-mono text-[9px] uppercase tracking-[0.12em] text-orange">
          SIMULATED — Connect GNS3 for live execution
        </span>
      </CardHeader>
      <CardContent className="space-y-4 pt-4">
        <div className="min-h-[180px] rounded-md border border-black bg-black p-4 font-mono text-xs leading-6 text-green">
          {terminalLines.map((line, idx) => (
            <div key={idx}>{line}</div>
          ))}
          {target && terminalLines.length < baseCommands.length && (
            <span className="animate-pulse">_</span>
          )}
          {!target && (
            <div className="text-slate-500">Auto-response engine idle. Awaiting rogue classification...</div>
          )}
        </div>
        <Button 
          className="w-full border-purple/50 bg-purple/10 text-purple hover:bg-purple/20 transition-all font-bold" 
          onClick={() => target && onExecute(target.ip)} 
          disabled={!target || busy || target.status === "QUARANTINED"}
        >
          {busy ? <Loader2 className="animate-spin mr-1" size={15} /> : <Play size={15} className="mr-1" />}
          Execute Quarantine Action {target ? `for ${target.ip}` : ""}
        </Button>
      </CardContent>
    </Card>
  );
}
