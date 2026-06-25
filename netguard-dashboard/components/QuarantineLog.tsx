"use client";

import { Download } from "lucide-react";

import { Button, Card, CardContent, CardHeader, CardTitle } from "./ui";
import type { QuarantineAction } from "../types";

function exportCsv(actions: QuarantineAction[]) {
  const rows = [
    ["Time", "IP", "MAC", "Action", "VLAN", "Status"],
    ...actions.map((action) => [
      action.timestamp, 
      action.ip, 
      action.mac, 
      action.action ?? "quarantine", 
      String(action.vlan), 
      action.success ? "SUCCESS" : action.note?.includes("SIMULATED") ? "SIMULATED" : "FAILED"
    ]),
  ];
  const csv = rows.map((row) => row.map((value) => `"${value.replaceAll('"', '""')}"`).join(",")).join("\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "netguard-quarantine-log.csv";
  link.click();
  URL.revokeObjectURL(url);
}

function getStatusDetails(action: QuarantineAction) {
  if (action.success) {
    return { text: "SUCCESS", color: "text-[#00ff88] bg-[#00ff88]/10 border-[#00ff88]/20" };
  } else if (action.note?.toLowerCase().includes("error") || action.note?.toLowerCase().includes("fail")) {
    return { text: "FAILED", color: "text-[#ff4444] bg-[#ff4444]/10 border-[#ff4444]/20" };
  } else {
    return { text: "SIMULATED", color: "text-[#00ff88] bg-[#00ff88]/10 border-[#00ff88]/20" };
  }
}

export function QuarantineLog({ actions }: { actions: QuarantineAction[] }) {
  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-white/5">
        <div>
          <CardTitle>Quarantine Audit Log</CardTitle>
          <p className="mt-1 text-xs text-text-secondary">Historical logs of all automated and manual quarantine events.</p>
        </div>
        <Button className="border-cyan/40 text-cyan hover:bg-cyan/5 font-bold" onClick={() => exportCsv(actions)}>
          <Download size={15} className="mr-1" />
          Export CSV
        </Button>
      </CardHeader>
      <CardContent>
        <div className="max-h-[360px] overflow-auto scrollbar-thin">
          <table className="min-w-[720px] w-full text-left text-sm">
            <thead className="sticky top-0 z-10 bg-card text-xs uppercase tracking-[0.16em] text-text-secondary border-b border-white/5">
              <tr>
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">IP</th>
                <th className="py-3 px-4">MAC</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">VLAN</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody>
              {actions.map((action, index) => {
                const status = getStatusDetails(action);
                return (
                  <tr key={`${action.ip}-${action.timestamp}-${index}`} className="border-b border-white/5 hover:bg-white/[0.015] transition-colors">
                    <td className="py-3 px-4 font-mono text-xs text-text-secondary">
                      {new Date(action.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 font-mono text-cyan">{action.ip}</td>
                    <td className="py-3 px-4 font-mono text-text-secondary">{action.mac}</td>
                    <td className="py-3 px-4 text-xs font-semibold uppercase tracking-wider text-text-primary">
                      {action.action ?? "quarantine"}
                    </td>
                    <td className="py-3 px-4 font-mono">{action.vlan}</td>
                    <td className="py-3 px-4">
                      <span className={`inline-flex items-center rounded px-2 py-0.5 text-[10px] font-bold border ${status.color}`}>
                        {status.text}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {!actions.length && (
            <p className="py-10 text-xs text-text-secondary text-center">No quarantine actions recorded in audit logs.</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
