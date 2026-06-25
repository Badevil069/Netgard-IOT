"use client";

import { Card, CardContent, CardHeader, CardTitle } from "./ui";
import type { TimelineEvent } from "../types";

const eventStyles = {
  device: { color: "bg-slate-400 border-slate-500/30", symbol: "⚪" },
  warning: { color: "bg-orange border-orange/30", symbol: "🟡" },
  rogue: { color: "bg-red border-red/30 animate-pulse", symbol: "🔴" },
  quarantine: { color: "bg-purple border-purple/30", symbol: "🟠" },
  contained: { color: "bg-green border-green/30", symbol: "🟢" },
};

export function EventTimeline({ events }: { events: TimelineEvent[] }) {
  const displayEvents = events.slice(0, 10); 

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <CardTitle>Event Timeline</CardTitle>
        <span className="font-mono text-xs text-text-secondary">{events.length} logs</span>
      </CardHeader>
      <CardContent>
        <div className="h-[320px] space-y-2 overflow-y-auto pr-1 scrollbar-thin">
          {displayEvents.map((event) => {
            const style = eventStyles[event.type] || eventStyles.device;
            return (
              <div
                key={event.id}
                className="grid grid-cols-[20px_1fr] gap-3 items-start rounded-md border border-white/5 bg-bg/45 p-3 hover:bg-white/[0.015] transition-colors"
              >
                <span className="text-sm leading-none pt-0.5" title={event.type}>
                  {style.symbol}
                </span>
                <div>
                  <p className="text-xs font-semibold leading-5 text-text-primary">{event.title}</p>
                  <p className="text-xs text-text-secondary">{event.description}</p>
                  <p className="mt-1 font-mono text-[10px] text-slate-500">
                    {new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </p>
                </div>
              </div>
            );
          })}
          {!events.length && (
            <p className="text-xs text-text-secondary text-center py-10">No security events logged.</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
