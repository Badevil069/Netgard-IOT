"use client";

import { Camera, Cpu, Lightbulb, Router, Thermometer, TriangleAlert } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "./ui";
import { cn } from "../lib/utils";
import type { Device } from "../types";

function iconFor(device: Device) {
  const name = device.name.toLowerCase();
  if (name.includes("camera")) return Camera;
  if (name.includes("thermostat")) return Thermometer;
  if (name.includes("bulb")) return Lightbulb;
  if (device.status === "ROGUE") return TriangleAlert;
  return Cpu;
}

function colorFor(status: Device["status"]) {
  if (status === "ROGUE") return "#ff4444";
  if (status === "QUARANTINED") return "#a855f7";
  return "#00ff88";
}

export function NetworkTopology({ devices }: { devices: Device[] }) {
  const visibleDevices = [...devices]
    .sort((a, b) => {
      const priority = { ROGUE: 0, QUARANTINED: 1, NORMAL: 2 };
      return priority[a.status] - priority[b.status] || b.unique_ports - a.unique_ports;
    })
    .slice(0, 10); // Limit to 10 for clean spacing
  const hiddenCount = Math.max(0, devices.length - visibleDevices.length);
  
  const center = { x: 225, y: 140 };
  const radiusX = 150;
  const radiusY = 90;

  const positioned = visibleDevices.map((device, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(visibleDevices.length, 1) - Math.PI / 2;
    return {
      device,
      x: center.x + Math.cos(angle) * radiusX,
      y: center.y + Math.sin(angle) * radiusY,
    };
  });

  return (
    <Card className="h-full overflow-hidden border border-border">
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <div>
          <CardTitle>Network Topology</CardTitle>
          <p className="mt-1 text-xs text-text-secondary">Visual threat containment map.</p>
        </div>
        {hiddenCount > 0 ? (
          <span className="rounded-md border border-border bg-bg/70 px-2 py-1 font-mono text-xs text-text-secondary">
            +{hiddenCount} more
          </span>
        ) : null}
      </CardHeader>
      <CardContent className="space-y-4">
        <svg viewBox="0 0 450 300" className="h-[270px] w-full bg-[#070b13] rounded-lg border border-border">
          <style>{`
            @keyframes topology-dash {
              to {
                stroke-dashoffset: -20;
              }
            }
            @keyframes node-pulse-grow {
              0% {
                r: 16;
                opacity: 0.8;
                stroke-width: 1px;
              }
              50% {
                r: 28;
                opacity: 0.1;
                stroke-width: 3px;
              }
              100% {
                r: 16;
                opacity: 0.8;
                stroke-width: 1px;
              }
            }
            .line-normal {
              stroke: #00ff88;
              stroke-width: 1.5px;
              stroke-opacity: 0.4;
            }
            .line-rogue {
              stroke: #ff4444;
              stroke-width: 2.5px;
              stroke-dasharray: 6 5;
              animation: topology-dash 0.8s linear infinite;
            }
            .line-quarantined {
              stroke: #a855f7;
              stroke-width: 1.5px;
              stroke-dasharray: 4 4;
              animation: topology-dash 1.5s linear infinite;
            }
            .pulse-ring {
              transform-origin: center;
              animation: node-pulse-grow 2s infinite ease-out;
            }
          `}</style>

          {/* Connection Lines */}
          {positioned.map(({ device, x, y }) => {
            const lineClass =
              device.status === "ROGUE"
                ? "line-rogue"
                : device.status === "QUARANTINED"
                  ? "line-quarantined"
                  : "line-normal";
            return (
              <line
                key={`line-${device.ip}`}
                x1={center.x}
                y1={center.y}
                x2={x}
                y2={y}
                className={lineClass}
              />
            );
          })}

          {/* Core Switch */}
          <circle cx={center.x} cy={center.y} r="32" fill="#111827" stroke="#00d4ff" strokeWidth="2" />
          <foreignObject x={center.x - 14} y={center.y - 20} width="28" height="28">
            <div className="grid h-7 w-7 place-items-center text-cyan">
              <Router size={20} />
            </div>
          </foreignObject>
          <text x={center.x} y={center.y + 18} textAnchor="middle" fill="#00d4ff" fontSize="7" className="font-mono tracking-widest font-bold">
            SWITCH
          </text>

          {/* Nodes */}
          {positioned.map(({ device, x, y }) => {
            const Icon = iconFor(device);
            const color = colorFor(device.status);
            const isRogue = device.status === "ROGUE";
            return (
              <g key={device.ip}>
                {/* Rogue outer pulse ring */}
                {isRogue && (
                  <circle
                    cx={x}
                    cy={y}
                    r="24"
                    fill="none"
                    stroke={color}
                    className="pulse-ring"
                  />
                )}
                {/* Main Node Circle */}
                <circle
                  cx={x}
                  cy={y}
                  r="16"
                  fill="#111827"
                  stroke={color}
                  strokeWidth="2"
                  className={cn(isRogue && "animate-pulse")}
                />
                <foreignObject x={x - 8} y={y - 8} width="16" height="16">
                  <div className="grid h-4 w-4 place-items-center" style={{ color }}>
                    <Icon size={12} />
                  </div>
                </foreignObject>
                
                {/* Node labels (IP and status) */}
                <text x={x} y={y + 26} textAnchor="middle" fill="#cbd5e1" fontSize="7.5" fontFamily="monospace" className="font-bold">
                  {device.ip}
                </text>
                <text x={x} y={y + 34} textAnchor="middle" fill={color} fontSize="7" fontFamily="monospace" className="font-semibold uppercase tracking-wider">
                  {device.status}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Live List Underneath */}
        <div className="grid max-h-[140px] gap-2 overflow-y-auto pr-1 scrollbar-thin sm:grid-cols-2">
          {visibleDevices.map((device) => (
            <div key={device.ip} className="flex items-center justify-between gap-2 rounded-md border border-white/5 bg-bg/55 px-2.5 py-1.5">
              <div className="min-w-0">
                <p className="truncate text-xs font-semibold text-text-primary">{device.name}</p>
                <p className="font-mono text-[10px] text-text-secondary">{device.ip}</p>
              </div>
              <span
                className={cn(
                  "shrink-0 rounded-full border px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider",
                  device.status === "ROGUE" && "border-red bg-red/10 text-red animate-pulse",
                  device.status === "QUARANTINED" && "border-purple bg-purple/10 text-purple",
                  device.status === "NORMAL" && "border-green bg-green/10 text-green",
                )}
              >
                {device.status}
              </span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
