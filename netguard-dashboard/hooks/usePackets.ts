"use client";

import { useEffect, useState } from "react";

import { getPackets } from "../lib/api";
import type { Packet } from "../types";

export function usePackets() {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [totalPackets, setTotalPackets] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    const poll = async () => {
      try {
        const data = await getPackets();
        if (!mounted) return;
        setPackets(data.packets);
        setTotalPackets(data.total_packets ?? data.packets.length);
        setError(null);
        setLoading(false);
      } catch (pollError) {
        if (!mounted) return;
        setError(pollError instanceof Error ? pollError.message : "Failed to load packets");
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

  return { packets, totalPackets, loading, error };
}
