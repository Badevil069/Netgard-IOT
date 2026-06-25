"use client";

import { useEffect, useRef, useState } from "react";

import type { Device, TrafficHistory } from "../types";

const MAX_POINTS = 60;

export function useTrafficHistory(devices: Device[]) {
  const historyRef = useRef<TrafficHistory>({});
  const [version, setVersion] = useState(0);

  useEffect(() => {
    const timestamp = new Date().toISOString();
    let updated = false;

    for (const device of devices) {
      const series = historyRef.current[device.ip] ?? [];
      const nextSeries = [...series, { timestamp, value: device.quarantined ? 0 : device.pps }].slice(-MAX_POINTS);
      historyRef.current[device.ip] = nextSeries;
      updated = true;
    }

    if (updated) {
      setVersion((value) => value + 1);
    }
  }, [devices]);

  return { history: historyRef.current, version };
}
