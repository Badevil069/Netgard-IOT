"use client";

import type { LucideIcon } from "lucide-react";
import { useSpring, animated } from "@react-spring/web";

import { Card } from "./ui";
import { cn } from "../lib/utils";

type MetricCardProps = {
  title: string;
  value: number | string;
  icon: LucideIcon;
  tone: "cyan" | "green" | "red" | "purple";
  pulse?: boolean;
  detail?: string;
};

const toneClasses = {
  cyan: "border-cyan/50 text-cyan",
  green: "border-green/50 text-green",
  red: "border-red/60 text-red",
  purple: "border-purple/50 text-purple",
};

// Cast animated.span as any to resolve strict TS compiler mismatch between React 18 and react-spring web typings
const AnimatedSpan = animated.span as any;

function AnimatedNumber({ value }: { value: number | string }) {
  const numeric = typeof value === "number" ? value : parseFloat(value);
  const isFloat = typeof value === "number" ? !Number.isInteger(value) : value.includes(".");
  
  const { num } = useSpring({
    from: { num: 0 },
    to: { num: isNaN(numeric) ? 0 : numeric },
    config: { mass: 1, tension: 170, friction: 26 },
  });

  if (isNaN(numeric)) {
    return <span>{value}</span>;
  }

  return (
    <AnimatedSpan>
      {num.to((val) => val.toFixed(isFloat ? 1 : 0))}
    </AnimatedSpan>
  );
}

export function MetricCard({ title, value, icon: Icon, tone, pulse, detail }: MetricCardProps) {
  return (
    <Card className={cn("p-3 transition-all duration-300", toneClasses[tone], pulse && "animate-pulseBorder")}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[11px] uppercase tracking-[0.14em] text-text-secondary">{title}</p>
          <p className="mt-1 font-mono text-2xl font-semibold leading-8 text-text-primary transition-all duration-300">
            <AnimatedNumber value={value} />
          </p>
          {detail ? <p className="mt-1 truncate text-xs text-text-secondary">{detail}</p> : null}
        </div>
        <div className="grid size-9 shrink-0 place-items-center rounded-md border border-current bg-current/10">
          <Icon size={18} />
        </div>
      </div>
    </Card>
  );
}
