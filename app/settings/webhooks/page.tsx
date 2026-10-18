"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Loader2, Bell } from "lucide-react";
import { WebhooksPanel } from "@/components/webhooks-panel";
import { api, type State } from "@/lib/types";

export default function WebhooksPage() {
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
          href="/#settings"
          className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg border hover:bg-neutral-100 dark:hover:bg-neutral-800 transition"
        >
          <ArrowLeft size={14} /> Back to Settings
        </Link>
      </div>

      {loading ? (
        <div className="p-16 text-center">
          <Loader2 size={24} className="animate-spin mx-auto opacity-50" />
        </div>
      ) : (
        <WebhooksPanel
          webhooks={state?.webhooks || []}
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
