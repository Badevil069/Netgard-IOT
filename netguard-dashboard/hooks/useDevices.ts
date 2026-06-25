"use client";

import { useEffect, useState } from "react";

import { getDevices } from "../lib/api";
import type { Device } from "../types";

export function useDevices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    const poll = async () => {
      try {
        const data = await getDevices();
        if (!mounted) return;
        setDevices(data.devices);
        setError(null);
        setLoading(false);
      } catch (pollError) {
        if (!mounted) return;
        setError(pollError instanceof Error ? pollError.message : "Failed to load devices");
        setLoading(false);
      }
    };

    void poll();
    const interval = setInterval(() => void poll(), 2000);

    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  return { devices, loading, error };
}
