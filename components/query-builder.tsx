"use client";

import { useId, useRef, useState } from "react";
import { Plus, X } from "lucide-react";
import { anyField, fieldLabel, newGroup, newRule, ruleOperators, type QueryFields, type BuilderGroup, type BuilderNode, type BuilderRule } from "@/lib/query-language";
import type { QueryView } from "@/lib/query-fields";

function choices(view: QueryView, field: string): string[] {
  if (field === "severity") return ["critical", "high", "medium", "low", "info", "none"];
  if (field === "status" && view === "findings") return ["open", "resolved", "accepted risk", "false positive"];
  if (field === "status" && view === "takeovers") return ["open", "resolved", "suppressed"];
  if (field === "status" && view === "scans") return ["queued", "running", "completed", "partial", "failed", "canceled", "retrying"];
  if (field === "category") return ["vulnerability", "secret", "port", "endpoint", "hazard", "host"];
  if (field === "exposure") return ["exposed", "clear"];
  if (field === "class") return ["ssrf_candidate", "redirect_candidate", "lfi_candidate", "sqli_candidate", "debug_flag", "sensitive_file"];
  if (field === "method") return ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
  if (field === "tool") return ["nuclei", "retire", "gitleaks", "httpx", "tlsx", "naabu", "katana", "dnsx", "subfinder", "gau"];
  if (field === "kind" && view === "changes") return ["asset", "port", "finding", "resolved", "certificate", "endpoint"];
  return [];
}

function RuleRow({ rule, fields, view, label, onChange, onRemove }: {
  rule: BuilderRule; fields: QueryFields; view: QueryView; label: string;
  onChange: (rule: BuilderRule) => void; onRemove: () => void;
}) {
  const id = useId();
  const type = rule.field === anyField ? "search" : fields[rule.field];
  const presence = rule.value === "*" && rule.field !== anyField;
  const operator = presence ? (rule.operator === "!=" ? "missing" : "exists") : rule.operator === ":" && type !== "text" && type !== "search" ? "=" : rule.operator;
  const options = type === "boolean" ? ["true", "false"] : choices(view, rule.field);
  const [customMode, setCustomMode] = useState(false);
  const custom = customMode || (options.length > 0 && rule.value !== "" && !options.includes(rule.value));
  return (
    <div className="builder-rule" role="group" aria-label={label}>
      <label><span>Field</span><select data-query-focus aria-label={`${label} field`} value={rule.field} onChange={e => {
        const field = e.target.value;
        onChange({ ...newRule(fields), field, operator: field === anyField || fields[field] === "text" ? ":" : "=" });
      }}>
        <option value={anyField}>Any field</option>
        {Object.keys(fields).map(field => <option key={field} value={field}>{fieldLabel(field)}</option>)}
      </select></label>
      <label><span>Operator</span><select aria-label={`${label} operator`} value={operator} onChange={e => {
        const op = e.target.value;
        onChange({ ...rule, operator: op === "exists" ? ":" : op === "missing" ? "!=" : op, value: op === "exists" || op === "missing" ? "*" : presence ? "" : rule.value });
      }}>
        {ruleOperators(type).map(op => <option key={op.value} value={op.value}>{op.label}</option>)}
      </select></label>
      <div className="builder-value">
        {presence ? <span className="builder-presence">{operator === "missing" ? "No observed value" : "Any observed value"}</span> : <>
          <label htmlFor={id}>Value</label>
          {options.length > 0 && !custom ? <select id={id} aria-label={`${label} value`} value={rule.value} onChange={e => { if (e.target.value === "__custom") { setCustomMode(true); onChange({ ...rule, value: "" }); } else onChange({ ...rule, value: e.target.value }); }}>
            <option value="">Select a value…</option>
            {options.map(value => <option key={value} value={value}>{value}</option>)}
            {type !== "boolean" && <option value="__custom">Custom value…</option>}
          </select> : <input id={id} aria-label={`${label} value`} type={type === "number" ? "number" : "text"} step={type === "number" ? "any" : undefined} value={rule.value} placeholder={type === "date" ? "2026-01-01 or ISO timestamp" : "Enter a value…"} maxLength={1024} onChange={e => onChange({ ...rule, value: e.target.value })} />}
          {custom && options.length > 0 && <button type="button" className="builder-suggestions" onClick={() => { setCustomMode(false); onChange({ ...rule, value: "" }); }}>Use suggested values</button>}
        </>}
      </div>
      <label className="builder-negate"><input type="checkbox" checked={rule.negate} onChange={e => onChange({ ...rule, negate: e.target.checked })} /> NOT<span className="sr-only"> {label}</span></label>
      <button type="button" className="builder-remove" aria-label={`Remove ${label.toLowerCase()}`} onClick={onRemove}><X size={16} /></button>
    </div>
  );
}

export function QueryBuilder({ group, fields, view, onChange, onRemove, path = "1", depth = 0 }: {
  group: BuilderGroup; fields: QueryFields; view: QueryView;
  onChange: (group: BuilderGroup) => void; onRemove?: () => void; path?: string; depth?: number;
}) {
  const ref = useRef<HTMLFieldSetElement>(null);
  const replace = (index: number, node: BuilderNode) => onChange({ ...group, children: group.children.map((child, i) => i === index ? node : child) });
  const remove = (index: number) => {
    onChange({ ...group, children: group.children.filter((_, i) => i !== index) });
    requestAnimationFrame(() => ref.current?.querySelector<HTMLSelectElement>("select")?.focus());
  };
  return (
    <fieldset className="builder-group" ref={ref}>
      <legend>{depth === 0 ? "Filter conditions" : `Condition group ${path}`}</legend>
      <div className="builder-group-heading">
        <label><span>Match</span><select data-query-focus={depth === 0 || undefined} aria-label={`Group ${path} join`} value={group.combinator} onChange={e => onChange({ ...group, combinator: e.target.value as "AND" | "OR" })}>
          <option value="AND">All conditions · AND</option><option value="OR">Any condition · OR</option>
        </select></label>
        <label className="builder-negate"><input type="checkbox" checked={group.negate} onChange={e => onChange({ ...group, negate: e.target.checked })} /> Exclude group (NOT)</label>
        {onRemove && <button type="button" className="builder-remove" aria-label={`Remove group ${path}`} onClick={onRemove}><X size={16} /></button>}
      </div>
      <div className="builder-children">
        {group.children.map((child, index) => <div key={index} className="builder-child">
          {index > 0 && <span className="builder-join">{group.combinator}</span>}
          {child.kind === "group" ? <QueryBuilder group={child} fields={fields} view={view} path={`${path}.${index + 1}`} depth={depth + 1} onChange={node => replace(index, node)} onRemove={() => remove(index)} /> : <RuleRow key={child.field} rule={child} fields={fields} view={view} label={`Condition ${path}.${index + 1}`} onChange={node => replace(index, node)} onRemove={() => remove(index)} />}
        </div>)}
      </div>
      {!group.children.length && <p className="builder-empty">No conditions. All records in the selected scope will be shown.</p>}
      <div className="builder-actions">
        <button type="button" onClick={() => onChange({ ...group, children: [...group.children, newRule(fields)] })}><Plus size={14} /> Add condition<span className="sr-only"> to group {path}</span></button>
        <button type="button" disabled={depth >= 11} onClick={() => onChange({ ...group, children: [...group.children, newGroup(fields)] })}><Plus size={14} /> Add group<span className="sr-only"> to group {path}</span></button>
      </div>
    </fieldset>
  );
}
