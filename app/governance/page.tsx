"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Loader2, Mail } from "lucide-react";
import { GovernanceView } from "@/components/governance-view";
import { api, type State } from "@/lib/types";

export default function GovernancePage() {
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
          href="/#governance"
          className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg border hover:bg-neutral-100 dark:hover:bg-neutral-800 transition"
        >
          <ArrowLeft size={14} /> Back to Workspace
        </Link>
      </div>

      <div className="page-heading">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Mail size={24} /> DNS & Email Governance
        </h1>
        <p className="text-sm opacity-70 mt-1">
          Evaluate SPF policies, DMARC enforcement, DKIM selector discovery, and mail exchange records.
        </p>
      </div>

      {loading ? (
        <div className="p-16 text-center">
          <Loader2 size={24} className="animate-spin mx-auto opacity-50" />
        </div>
      ) : (
        <GovernanceView dnsPosture={state?.dnsPosture || []} />
      )}
    </div>
  );
}
