"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Loader2, TriangleAlert } from "lucide-react";
import { HazardsView } from "@/components/hazards-view";
import { api, type State } from "@/lib/types";

export default function HazardsPage() {
  const [state, setState] = useState<State | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api("state")
      .then((res) => setState(res))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="min-h-screen p-6 md:p-10 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <Link
          href="/#hazards"
          className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg border hover:bg-neutral-100 dark:hover:bg-neutral-800 transition"
        >
          <ArrowLeft size={14} /> Back to Workspace
        </Link>
      </div>

      <div className="page-heading">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <TriangleAlert size={24} className="text-amber-500" /> Endpoint Parameter Hazard Triage
        </h1>
        <p className="text-sm opacity-70 mt-1">
          Heuristic attack surface triage of discovered URLs and parameter hazards (SSRF, LFI, Open Redirect, SQLi, Debug Flags).
        </p>
      </div>

      {loading ? (
        <div className="p-16 text-center">
          <Loader2 size={24} className="animate-spin mx-auto opacity-50" />
        </div>
      ) : (
        <HazardsView hazards={state?.hazards || []} canDelete={state?.me?.role === "owner"} mutate={async (path, method, data) => {
          await api(path, method, data);
          setState(await api("state"));
          return true;
        }} />
      )}
    </div>
  );
}
