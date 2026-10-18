"use client";

import { useState } from "react";
import {
  Bell,
  Plus,
  Trash2,
  Send,
  Loader2,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
} from "lucide-react";
import { api, dateTime, type NotificationWebhook } from "@/lib/types";

export function WebhooksPanel({
  webhooks = [],
  mutate,
}: {
  webhooks?: NotificationWebhook[];
  mutate?: (path: string, method: string, data?: unknown, message?: string) => Promise<boolean>;
}) {
  const [url, setUrl] = useState("");
  const [webhookType, setWebhookType] = useState<"slack" | "discord" | "generic">("slack");
  const [notifyOnNewAssets, setNotifyOnNewAssets] = useState(true);
  const [notifyOnNewPorts, setNotifyOnNewPorts] = useState(true);
  const [notifyOnHighFindings, setNotifyOnHighFindings] = useState(true);
  const [notifyOnTakeovers, setNotifyOnTakeovers] = useState(true);

  const [saving, setSaving] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ id: string; success: boolean; msg: string } | null>(null);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setSaving(true);
    try {
      if (mutate) {
        await mutate(
          "webhooks",
          "POST",
          {
            url: url.trim(),
            webhookType,
            notifyOnNewAssets,
            notifyOnNewPorts,
            notifyOnHighFindings,
            notifyOnTakeovers,
            enabled: true,
          },
          "Webhook registered successfully",
        );
      } else {
        await api("webhooks", "POST", {
          url: url.trim(),
          webhookType,
          notifyOnNewAssets,
          notifyOnNewPorts,
          notifyOnHighFindings,
          notifyOnTakeovers,
          enabled: true,
        });
      }
      setUrl("");
    } catch (err: any) {
      alert(err.message || "Failed to create webhook");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to remove this webhook?")) return;
    try {
      if (mutate) {
        await mutate(`webhooks?id=${id}`, "DELETE", undefined, "Webhook deleted");
      } else {
        await api(`webhooks?id=${id}`, "DELETE");
      }
    } catch (err: any) {
      alert(err.message || "Failed to delete webhook");
    }
  };

  const handleTest = async (id: string) => {
    setTestingId(id);
    setFeedback(null);
    try {
      await api("webhooks/test", "POST", { id });
      setFeedback({ id, success: true, msg: "Test notification delivered!" });
    } catch (err: any) {
      setFeedback({ id, success: false, msg: err.message || "Delivery failed" });
    } finally {
      setTestingId(null);
    }
  };

  return (
    <div className="space-y-8 max-w-4xl">
      {/* Intro section */}
      <div className="section-title audit-intro">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Bell size={18} /> Attack Surface Delta Webhooks
          </h2>
          <p className="text-sm opacity-70 mt-1">
            Dispatch real-time alerts to Slack, Discord, or generic HTTP endpoints when new assets,
            ports, high/critical findings, or subdomain takeovers are confirmed.
          </p>
        </div>
      </div>

      {/* Add Webhook Form */}
      <form onSubmit={handleCreate} className="p-5 border rounded-xl space-y-4 bg-neutral-50/50 dark:bg-neutral-900/40">
        <h3 className="text-sm font-semibold">Register New Webhook</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2">
            <label className="block text-xs font-semibold mb-1 opacity-80">Webhook Target URL</label>
            <input
              type="url"
              required
              placeholder="https://hooks.slack.com/services/..."
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full px-3 py-1.5 rounded-md border text-sm"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold mb-1 opacity-80">Payload Format</label>
            <select
              value={webhookType}
              onChange={(e) => setWebhookType(e.target.value as any)}
              className="w-full px-3 py-1.5 rounded-md border text-sm"
            >
              <option value="slack">Slack Incoming Webhook</option>
              <option value="discord">Discord Webhook</option>
              <option value="generic">Generic JSON HTTP POST</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-xs font-semibold mb-2 opacity-80">Notification Triggers</label>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={notifyOnNewAssets}
                onChange={(e) => setNotifyOnNewAssets(e.target.checked)}
              />
              <span>New Assets</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={notifyOnNewPorts}
                onChange={(e) => setNotifyOnNewPorts(e.target.checked)}
              />
              <span>Exposed Ports</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={notifyOnHighFindings}
                onChange={(e) => setNotifyOnHighFindings(e.target.checked)}
              />
              <span>High/Crit Findings</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={notifyOnTakeovers}
                onChange={(e) => setNotifyOnTakeovers(e.target.checked)}
              />
              <span>Subdomain Takeovers</span>
            </label>
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            type="submit"
            disabled={saving || !url.trim()}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-neutral-900 text-white dark:bg-white dark:text-neutral-900 text-xs font-semibold hover:opacity-90 disabled:opacity-50"
          >
            {saving ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
            Register Webhook
          </button>
        </div>
      </form>

      {/* Webhook List */}
      <div>
        <h3 className="text-sm font-semibold mb-3">Configured Webhooks ({webhooks.length})</h3>
        {webhooks.length === 0 ? (
          <p className="text-sm opacity-60 italic">No webhooks registered yet.</p>
        ) : (
          <div className="space-y-3">
            {webhooks.map((wh) => (
              <div
                key={wh.id}
                className="p-4 border rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4 bg-white dark:bg-neutral-900/60"
              >
                <div className="space-y-1.5 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-xs px-2 py-0.5 rounded bg-neutral-200 dark:bg-neutral-800 uppercase">
                      {wh.webhookType}
                    </span>
                    <span className="text-xs text-emerald-600 dark:text-emerald-400 font-semibold">
                      {wh.enabled ? "Active" : "Disabled"}
                    </span>
                  </div>
                  <div className="font-mono text-xs opacity-80 break-all">{wh.url}</div>
                  <div className="flex flex-wrap gap-1.5 text-[11px] opacity-70 pt-1">
                    {wh.notifyOnNewAssets && <span className="px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800">Assets</span>}
                    {wh.notifyOnNewPorts && <span className="px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800">Ports</span>}
                    {wh.notifyOnHighFindings && <span className="px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800">High/Crit</span>}
                    {wh.notifyOnTakeovers && <span className="px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800">Takeovers</span>}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    disabled={testingId === wh.id}
                    onClick={() => handleTest(wh.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded border hover:bg-neutral-100 dark:hover:bg-neutral-800 transition"
                  >
                    {testingId === wh.id ? <Loader2 size={12} className="animate-spin" /> : <Send size={12} />}
                    Test
                  </button>
                  <button
                    onClick={() => handleDelete(wh.id)}
                    className="p-1.5 text-xs rounded border hover:bg-rose-50 hover:text-rose-600 dark:hover:bg-rose-950/40 transition"
                    title="Delete webhook"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>

                {feedback && feedback.id === wh.id && (
                  <div className={`w-full text-xs flex items-center gap-1.5 mt-2 ${feedback.success ? "text-emerald-600" : "text-rose-600"}`}>
                    {feedback.success ? <CheckCircle2 size={14} /> : <AlertCircle size={14} />}
                    {feedback.msg}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
