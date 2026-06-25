"use client";

import { Cpu, FileText, Lock, Network, RadioTower, TerminalSquare } from "lucide-react";

const items = [
  { label: "Devices", icon: Cpu },
  { label: "Topology", icon: Network },
  { label: "Traffic", icon: RadioTower },
  { label: "Response", icon: TerminalSquare },
  { label: "Audit", icon: FileText },
  { label: "Containment", icon: Lock },
];

export function Sidebar() {
  return (
    <aside className="hidden w-20 border-r border-border bg-card/80 px-3 py-5 lg:block">
      <nav className="flex flex-col gap-3">
        {items.map((item) => (
          <button
            key={item.label}
            className="grid h-12 place-items-center rounded-lg border border-white/5 text-text-secondary transition hover:border-cyan/40 hover:text-cyan"
            title={item.label}
            type="button"
          >
            <item.icon size={20} />
          </button>
        ))}
      </nav>
    </aside>
  );
}
