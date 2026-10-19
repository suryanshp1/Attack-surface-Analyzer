"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Loader2, Flame } from "lucide-react";
import { TakeoversView } from "@/components/takeovers-view";
import { api, type State } from "@/lib/types";

export default function TakeoversPage() {
  const [state, setState] = useState<State | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchState = () => {
    return api("state")
      .then((res) => setState(res))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchState();
  }, []);

  return (
    <div className="min-h-screen p-6 md:p-10 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <Link
          href="/#takeovers"
          className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg border hover:bg-neutral-100 dark:hover:bg-neutral-800 transition"
        >
          <ArrowLeft size={14} /> Back to Workspace
        </Link>
      </div>

      <div className="page-heading">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Flame size={24} className="text-rose-500" /> Subdomain Takeover Dashboard
        </h1>
        <p className="text-sm opacity-70 mt-1">
          Dangling CNAMEs pointing to orphaned third-party cloud services (AWS S3, GitHub Pages, Heroku, Fastly, Shopify, Ghost, Surge).
        </p>
      </div>

      {loading ? (
        <div className="p-16 text-center">
          <Loader2 size={24} className="animate-spin mx-auto opacity-50" />
        </div>
      ) : (
        <TakeoversView
          takeovers={state?.takeovers || []}
          mutate={async (path, method, data) => {
            await api(path, method, data);
            await fetchState();
            return true;
          }}
        />
      )}
    </div>
  );
}
