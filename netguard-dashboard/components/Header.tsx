"use client";

import { Activity, Clock3, RadioTower, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "./ui";
import type { SummaryStats } from "../types";

export function Header({ stats }: { stats?: SummaryStats }) {
  const [mounted, setMounted] = useState(false);
  const [clock, setClock] = useState(() => new Date());

  useEffect(() => {
    setMounted(true);
    const interval = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  const threatLevel = stats?.threat_level ?? "GREEN";
  const levelClass =
    threatLevel === "RED"
      ? "border-red text-red bg-red/10"
      : threatLevel === "YELLOW"
        ? "border-orange text-orange bg-orange/10"
        : "border-green text-green bg-green/10";

  return (
    <header className="sticky top-0 z-30 border-b border-border bg-bg/90 px-4 py-3 backdrop-blur md:px-6">
      <div className="mx-auto flex max-w-[1800px] flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3 sm:w-1/3">
          <div className="grid size-9 place-items-center rounded-lg border border-cyan/40 bg-cyan/10 text-cyan shadow-glow">
            <ShieldCheck size={20} />
          </div>
          <div>
            <h1 className="text-lg font-semibold leading-5 text-text-primary">NetGuard IoT</h1>
            <p className="text-xs text-text-secondary">Threat Detection System</p>
          </div>
        </div>

        <div className="flex justify-start sm:justify-center sm:w-1/3">
          <Badge className="border-cyan/40 bg-cyan/10 text-cyan">
            <Clock3 size={12} className="mr-1.5" />
            <span className="font-mono text-xs">{mounted ? clock.toLocaleTimeString() : "--:--:--"}</span>
          </Badge>
        </div>

        <div className="flex flex-wrap items-center gap-2 sm:justify-end sm:w-1/3">
          <Badge className={levelClass}>{threatLevel}</Badge>
          <Badge className="border-green/50 bg-green/10 text-green">
            <Activity size={12} className="mr-1.5" />
            {stats?.system_status ?? "ONLINE"}
          </Badge>
          <Badge className="border-slate-600 bg-slate-900/70 text-text-secondary">
            <RadioTower size={12} className="mr-1.5" />
            2s poll
          </Badge>
        </div>
      </div>
    </header>
  );
}
