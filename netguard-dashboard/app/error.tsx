"use client";

export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <html lang="en">
      <body className="flex min-h-screen items-center justify-center bg-[#0a0e1a] p-6 text-slate-100">
        <div className="max-w-lg rounded-2xl border border-slate-800 bg-slate-900/90 p-6 shadow-2xl">
          <p className="text-sm uppercase tracking-[0.3em] text-cyan-300">NetGuard Error Boundary</p>
          <h1 className="mt-3 text-2xl font-semibold">Dashboard component crashed</h1>
          <p className="mt-4 text-sm text-slate-400">{error.message}</p>
          <button
            onClick={reset}
            className="mt-6 rounded-xl border border-cyan-400/30 bg-cyan-400/10 px-4 py-2 text-sm text-cyan-200 transition hover:bg-cyan-400/20"
          >
            Retry
          </button>
        </div>
      </body>
    </html>
  );
}
