"use client";

import { useState } from "react";
import { Bell, Plus, Trash2, Send, Loader2 } from "lucide-react";
import { api, type NotificationWebhook } from "@/lib/types";

type Feedback = { id: string; success: boolean; message: string };
export function WebhooksPanel({
  webhooks = [],
  mutate,
  canManage = false,
}: {
  webhooks?: NotificationWebhook[];
  mutate?: (path: string, method: string, data?: unknown, message?: string) => Promise<boolean>;
  canManage?: boolean;
}) {
  const [url, setUrl] = useState("");
  const [webhookType, setWebhookType] = useState<"slack" | "discord" | "generic">("slack");
  const [triggers, setTriggers] = useState({
    notifyOnNewAssets: true, notifyOnNewPorts: true,
    notifyOnHighFindings: true, notifyOnTakeovers: true,
  });
  const [busyId, setBusyId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  async function save(path: string, method: string, data: unknown, message: string) {
    if (mutate) return mutate(path, method, data, message);
    await api(path, method, data);
    return true;
  }

  async function create(event: React.FormEvent) {
    event.preventDefault();
    setFeedback(null);
    try {
      const destination = new URL(url.trim());
      if (destination.protocol !== "https:" || (destination.port && destination.port !== "443") || destination.username || destination.password || destination.hash) {
        throw new Error("Use an HTTPS URL on port 443 without user credentials or a fragment.");
      }
    } catch (error) {
      setFeedback({ id: "form", success: false, message: error instanceof Error ? error.message : "Enter a valid HTTPS URL." });
      return;
    }
    setBusyId("form");
    try {
      const ok = await save("webhooks", "POST", { url: url.trim(), webhookType, ...triggers, enabled: true }, "Webhook registered");
      if (!ok) throw new Error("Webhook was not saved. Your entries have been kept; review the error and try again.");
      setUrl("");
      setFeedback({ id: "form", success: true, message: "Webhook registered. Its destination is masked in the list below." });
    } catch (error) {
      setFeedback({ id: "form", success: false, message: error instanceof Error ? error.message : "Unable to save webhook." });
    } finally {
      setBusyId(null);
    }
  }

  async function remove(id: string) {
    setBusyId(id);
    setFeedback(null);
    try {
      if (!await save(`webhooks?id=${encodeURIComponent(id)}`, "DELETE", undefined, "Webhook deleted")) {
        throw new Error("Webhook was not deleted. Try again.");
      }
      setPendingDelete(null);
    } catch (error) {
      setFeedback({ id, success: false, message: error instanceof Error ? error.message : "Unable to delete webhook." });
    } finally {
      setBusyId(null);
    }
  }

  async function test(id: string) {
    setBusyId(id);
    setFeedback(null);
    try {
      await api("webhooks/test", "POST", { id });
      setFeedback({ id, success: true, message: "Test notification delivered." });
    } catch (error) {
      setFeedback({ id, success: false, message: error instanceof Error ? error.message : "Delivery failed. Try again." });
    } finally {
      setBusyId(null);
    }
  }

  const feedbackFor = (id: string) => feedback?.id === id && (
    <p id={id === "form" ? "webhook-form-feedback" : undefined}
      className={`webhook-feedback ${feedback.success ? "webhook-feedback-success" : "webhook-feedback-error"}`}
      role={feedback.success ? "status" : "alert"}>{feedback.message}</p>
  );

  return (
    <div className="webhooks-panel">
      <div className="section-title audit-intro">
        <div>
          <h2><Bell size={18} /> Notification webhooks</h2>
          <p>Send changes in assets, ports, findings, and takeover candidates to Slack, Discord, or an HTTPS endpoint.</p>
        </div>
      </div>
      {canManage ? (
        <form className="webhook-card" onSubmit={create}>
          <h3>Register a webhook</h3>
          <fieldset disabled={busyId !== null} className="webhook-fields">
            <legend className="sr-only">Webhook configuration</legend>
            <div className="webhook-inputs">
              <label htmlFor="webhook-url">Destination URL
                <input id="webhook-url" type="url" required maxLength={4096}
                  className="text-input" placeholder="https://hooks.slack.com/services/…"
                  value={url} onChange={(event) => setUrl(event.target.value)}
                  aria-describedby={`webhook-url-hint${feedback?.id === "form" && !feedback.success ? " webhook-form-feedback" : ""}`} />
              </label>
              <label htmlFor="webhook-format">Payload format
                <select id="webhook-format" className="text-input" value={webhookType}
                  onChange={(event) => setWebhookType(event.target.value as typeof webhookType)}>
                  <option value="slack">Slack</option><option value="discord">Discord</option><option value="generic">Generic JSON</option>
                </select>
              </label>
            </div>
            <p id="webhook-url-hint" className="field-hint">Public HTTPS on port 443. Private destinations and redirects are blocked.</p>
            <fieldset className="webhook-triggers">
              <legend>Notify me about</legend>
              {(Object.entries({ notifyOnNewAssets: "New assets", notifyOnNewPorts: "New ports", notifyOnHighFindings: "High or critical findings", notifyOnTakeovers: "Takeover candidates" }) as [keyof typeof triggers, string][]).map(([key, label]) => (
                <label key={key}><input type="checkbox" checked={triggers[key]}
                  onChange={(event) => setTriggers({ ...triggers, [key]: event.target.checked })} />{label}</label>
              ))}
            </fieldset>
            <div className="webhook-form-actions">
              <button type="submit" className="button button-primary" disabled={!url.trim() || webhooks.length >= 32}>
                {busyId === "form" ? <Loader2 size={16} className="spin" /> : <Plus size={16} />}
                {busyId === "form" ? "Registering…" : "Register webhook"}
              </button>
            </div>
          </fieldset>
          {webhooks.length >= 32 && <p className="field-hint">The 32-webhook limit has been reached. Remove a destination before adding another.</p>}
          {feedbackFor("form")}
        </form>
      ) : <p className="field-hint">Owners can register, test, and remove webhooks. Destination credentials are hidden for every role.</p>}
      <section aria-labelledby="configured-webhooks">
        <h3 id="configured-webhooks" className="webhook-list-title">Configured webhooks <span className="muted">({webhooks.length})</span></h3>
        {!webhooks.length ? (
          <div className="empty-state"><Bell size={28} /><h3>No webhooks configured</h3><p>{canManage ? "Register a destination above to receive change notifications." : "An owner can add a notification destination."}</p></div>
        ) : <div className="webhook-list">{webhooks.map((wh) => (
          <article className="webhook-card" key={wh.id} aria-label={`${wh.webhookType} webhook`}>
            <div className="webhook-row">
              <div className="webhook-details">
                <div className="webhook-badges"><span className="badge">{wh.webhookType}</span><span className={`badge ${wh.enabled ? "badge-success" : "badge-neutral"}`}>{wh.enabled ? "Enabled" : "Disabled"}</span></div>
                <p className="webhook-destination">{wh.url}</p>
                <p className="field-hint">Destination credentials are hidden.</p>
                <div className="webhook-badges">
                  {wh.notifyOnNewAssets && <span className="badge">Assets</span>}
                  {wh.notifyOnNewPorts && <span className="badge">Ports</span>}
                  {wh.notifyOnHighFindings && <span className="badge">High / critical</span>}
                  {wh.notifyOnTakeovers && <span className="badge">Takeovers</span>}
                </div>
              </div>
              {canManage && <div className="webhook-actions">
                <button type="button" className="button button-secondary" disabled={busyId !== null} onClick={() => test(wh.id)}>
                  {busyId === wh.id ? <Loader2 size={16} className="spin" /> : <Send size={16} />} Test
                </button>
                <button type="button" className="icon-button" aria-label={`Remove ${wh.webhookType} webhook`} disabled={busyId !== null}
                  onClick={() => { setPendingDelete(wh.id); setFeedback(null); }}><Trash2 size={17} /></button>
              </div>}
            </div>
            {pendingDelete === wh.id && <div className="webhook-delete-confirm" role="group" aria-label="Confirm webhook removal">
              <p>Remove this destination? Future notifications will stop.</p>
              <button type="button" className="button button-secondary" disabled={busyId !== null} onClick={() => setPendingDelete(null)}>Keep webhook</button>
              <button type="button" className="button button-danger" disabled={busyId !== null} onClick={() => remove(wh.id)}>Remove webhook</button>
            </div>}
            {feedbackFor(wh.id)}
          </article>
        ))}</div>}
      </section>
    </div>
  );
}
