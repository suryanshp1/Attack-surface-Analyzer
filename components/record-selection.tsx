"use client";

import { useEffect, useRef, useState } from "react";
import { Loader2, Trash2 } from "lucide-react";

export function useRecordSelection(ids: string[], scope: string) {
  const [state, setState] = useState<{ scope: string; ids: Set<string> }>({
    scope,
    ids: new Set(),
  });
  if (state.scope !== scope) setState({ scope, ids: new Set() });
  // A filter/scope change clears selection synchronously, including Back and
  // refresh. New live results are never implicitly added to "select all".
  const selected = new Set(
    ids.filter((id) => state.scope === scope && state.ids.has(id)),
  );
  const replace = (values: string[]) =>
    setState({ scope, ids: new Set(values) });
  const toggle = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    replace([...next]);
  };
  const togglePage = (page: string[]) => {
    const next = new Set(selected);
    const all = page.every((id) => next.has(id));
    page.forEach((id) => {
      if (all) next.delete(id);
      else next.add(id);
    });
    replace([...next]);
  };
  return {
    selected,
    toggle,
    togglePage,
    replace,
    all: () => replace(ids),
    total: new Set(ids).size,
  };
}

export function SelectionCheckbox({
  label,
  checked,
  mixed = false,
  onChange,
}: {
  label: string;
  checked: boolean;
  mixed?: boolean;
  onChange: () => void;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = mixed;
  }, [mixed]);
  return (
    <label
      className="record-checkbox"
      onClick={(event) => event.stopPropagation()}
    >
      <input
        ref={ref}
        type="checkbox"
        aria-label={label}
        checked={checked}
        onChange={onChange}
      />
    </label>
  );
}

type Mutation = (
  path: string,
  method: string,
  data?: unknown,
  message?: string,
) => Promise<boolean>;

export function BulkDeleteToolbar({
  selection,
  resource,
  mutate,
  pageIDs,
}: {
  selection: ReturnType<typeof useRecordSelection>;
  resource:
    | "findings"
    | "assets"
    | "endpoints"
    | "scans"
    | "hazards"
    | "takeovers";
  mutate: Mutation;
  pageIDs?: string[];
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [pending, setPending] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    if (pending.length && !dialog.current?.open) dialog.current?.showModal();
    if (!pending.length && dialog.current?.open) dialog.current.close();
  }, [pending]);

  async function remove() {
    setBusy(true);
    setError("");
    let completed = 0;
    try {
      // Each bounded batch is atomic. Only IDs confirmed by the user are sent;
      // matching records arriving during deletion are never included.
      while (completed < pending.length) {
        const batch = pending.slice(completed, completed + 100);
        const ok = await mutate(
          resource,
          "DELETE",
          { ids: batch },
          `Deleted ${completed + batch.length} of ${pending.length} selected records`,
        );
        if (!ok) {
          setError(
            `Deletion stopped after ${completed} confirmed records. Refresh to verify the remaining records, then retry or cancel.`,
          );
          setProgress(0);
          setPending(pending.slice(completed));
          return;
        }
        completed += batch.length;
        setProgress(completed);
        selection.replace(
          [...selection.selected].filter(
            (id) => !pending.slice(0, completed).includes(id),
          ),
        );
      }
      setPending([]);
    } catch {
      setError(
        `${completed} records deleted. Deletion stopped; refresh before retrying.`,
      );
      setPending(pending.slice(completed));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div
        className="bulk-record-actions"
        aria-label={`${resource} selection actions`}
      >
        <span role="status">
          {selection.selected.size} selected · {selection.total} matching
          records
        </span>
        {pageIDs && (
          <button
            type="button"
            className="button"
            disabled={!pageIDs.length || busy}
            onClick={() => selection.togglePage(pageIDs)}
          >
            {pageIDs.length > 0 &&
            pageIDs.every((id) => selection.selected.has(id))
              ? "Deselect"
              : "Select"}{" "}
            this page ({pageIDs.length})
          </button>
        )}
        <button
          type="button"
          className="button"
          disabled={!selection.total || busy}
          onClick={selection.all}
        >
          Select all {selection.total} matching
        </button>
        <button
          type="button"
          className="button"
          disabled={!selection.selected.size || busy}
          onClick={() => selection.replace([])}
        >
          Clear selection
        </button>
        <button
          type="button"
          className="button button-danger"
          disabled={!selection.selected.size || busy}
          onClick={() => {
            setError("");
            setProgress(0);
            setPending([...selection.selected]);
          }}
        >
          <Trash2 size={15} aria-hidden="true" /> Delete selected (
          {selection.selected.size})
        </button>
      </div>
      <dialog
        ref={dialog}
        className="modal bulk-delete-dialog"
        aria-labelledby="bulk-delete-heading"
        aria-busy={busy}
        tabIndex={-1}
        onKeyDown={(event) => {
          if (event.key !== "Tab") return;
          const buttons = Array.from(
            event.currentTarget.querySelectorAll<HTMLButtonElement>(
              "button:not([disabled])",
            ),
          );
          const first = buttons[0],
            last = buttons[buttons.length - 1];
          if (!first) {
            event.preventDefault();
            event.currentTarget.focus();
          } else if (
            event.shiftKey &&
            (document.activeElement === first ||
              document.activeElement === event.currentTarget)
          ) {
            event.preventDefault();
            last.focus();
          } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first.focus();
          }
        }}
        onCancel={(event) => {
          event.preventDefault();
          if (!busy) setPending([]);
        }}
      >
        <div className="modal-heading">
          <h2 id="bulk-delete-heading">
            Delete {pending.length} selected {resource}?
          </h2>
        </div>
        <p className="modal-lead">
          Only the selected records will be removed from active views, reports,
          and MCP results. This includes selections on other pages.
        </p>
        <p className="field-hint">
          Deletion is recorded in the audit log. Internal history and triage
          notes are retained.{" "}
          {resource === "scans"
            ? "Only finished scan records can be deleted. Their observations and recovery checkpoints are retained internally."
            : "A new scan can bring deleted observations back if it sees them again."}{" "}
          Deletion does not resolve findings or prove an asset is safe.
        </p>
        {resource === "assets" && (
          <p className="field-hint">
            The selected assets and their nested endpoints leave active
            inventory. Findings and scan history remain available.
          </p>
        )}
        {busy && (
          <p role="status" className="field-hint">
            Deleting records… {progress} of {pending.length}
          </p>
        )}
        {error && (
          <p role="alert" className="form-error">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <button
            autoFocus
            type="button"
            className="button"
            disabled={busy}
            onClick={() => setPending([])}
          >
            Cancel
          </button>
          <button
            type="button"
            className="button button-danger"
            disabled={busy || !pending.length}
            onClick={() => void remove()}
          >
            {busy ? (
              <Loader2 size={15} className="spin" aria-hidden="true" />
            ) : (
              <Trash2 size={15} aria-hidden="true" />
            )}
            {busy ? "Deleting…" : "Delete records"}
          </button>
        </div>
      </dialog>
    </>
  );
}
