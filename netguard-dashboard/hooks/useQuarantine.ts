"use client";

import { useEffect, useState } from "react";

import { getQuarantineLog } from "../lib/api";
import type { QuarantineAction } from "../types";

export function useQuarantine() {
  const [actions, setActions] = useState<QuarantineAction[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    const poll = async () => {
      try {
        const data = await getQuarantineLog();
        if (!mounted) return;
        setActions(data.actions);
        setError(null);
        setLoading(false);
      } catch (pollError) {
        if (!mounted) return;
        setError(pollError instanceof Error ? pollError.message : "Failed to load quarantine log");
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

  return { actions, loading, error };
}
