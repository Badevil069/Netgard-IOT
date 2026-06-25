"use client";

import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "./ui";
import type { Device, TrafficHistory } from "../types";

type ChartRow = {
  timestamp: string;
  label: string;
  [ip: string]: string | number;
};

function getLineColor(status: Device["status"], index: number): string {
  if (status === "ROGUE") return "#ff4444"; // red rogue
  if (status === "QUARANTINED") return "#a855f7"; // purple quarantine
  const normalColors = ["#00ff88", "#00d4ff", "#38bdf8"]; // green, cyan, blue
  return normalColors[index % normalColors.length];
}

export function TrafficGraph({ devices, history }: { devices: Device[]; history: TrafficHistory }) {
  // Sort devices to prioritize showing active/risk devices in the graph
  const visibleDevices = [...devices]
    .sort((a, b) => {
      const priority = { ROGUE: 0, QUARANTINED: 1, NORMAL: 2 };
      return priority[a.status] - priority[b.status] || b.pps - a.pps;
    })
    .slice(0, 8);

  const maxLength = Math.max(0, ...Object.values(history).map((series) => series.length));
  
  // Format history into rows for Recharts LineChart
  const rows: ChartRow[] = Array.from({ length: maxLength }).map((_, index) => {
    const firstSeries = Object.values(history)[0] ?? [];
    const timestamp = firstSeries[index]?.timestamp ?? new Date().toISOString();
    const row: ChartRow = {
      timestamp,
      label: new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    };
    for (const device of visibleDevices) {
      row[device.ip] = history[device.ip]?.[index]?.value ?? 0;
    }
    return row;
  });

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <div>
          <CardTitle>Real-Time Traffic (PPS)</CardTitle>
          <p className="mt-1 text-xs text-text-secondary">Packets per second timeline per device (60-sample window).</p>
        </div>
        <span className="font-mono text-xs text-cyan">{rows.length} points</span>
      </CardHeader>
      <CardContent>
        <div className="h-[300px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={rows} margin={{ top: 8, right: 18, left: -10, bottom: 0 }}>
              <CartesianGrid stroke="#1f2937" strokeDasharray="3 5" vertical={false} />
              <XAxis dataKey="label" stroke="#64748b" tick={{ fontSize: 10, fontFamily: "monospace" }} minTickGap={30} />
              <YAxis stroke="#64748b" tick={{ fontSize: 10, fontFamily: "monospace" }} width={42} />
              <Tooltip 
                contentStyle={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "6px" }}
                labelStyle={{ fontSize: "11px", color: "#94a3b8", fontFamily: "monospace" }}
                itemStyle={{ fontSize: "11px", fontFamily: "monospace" }}
              />
              <Legend wrapperStyle={{ fontSize: 11, color: "#94a3b8", paddingTop: "10px" }} />
              {visibleDevices.map((device, index) => (
                <Line
                  key={device.ip}
                  dataKey={device.ip}
                  dot={false}
                  isAnimationActive={false}
                  name={`${device.name} (${device.ip})`}
                  stroke={getLineColor(device.status, index)}
                  strokeWidth={device.status === "ROGUE" ? 3 : 1.5}
                  type="monotone"
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
