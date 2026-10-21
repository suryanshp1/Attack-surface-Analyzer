"use client";

import { useId, useRef, useState } from "react";
import { ArrowRight, Braces, Check, CircleHelp, X } from "lucide-react";
import { QueryBuilder } from "@/components/query-builder";
import { compileQuery, builderFromQuery, builderToQuery, builderError, type BuilderGroup } from "@/lib/query-language";
import { queryExamples, queryFields, type QueryView } from "@/lib/query-fields";
import { setWorkspaceQuery, useWorkspaceRoute } from "@/lib/workspace-route";

export function QueryFilter({
  view,
  count,
}: {
  view: QueryView;
  count: number;
}) {
  const { query } = useWorkspaceRoute();
  return <QueryEditor key={view} view={view} query={query} count={count} />;
}
function QueryEditor({
  view,
  query,
  count,
}: {
  view: QueryView;
  query: string;
  count: number;
}) {
  const fields = queryFields[view];
  const initialBuilder = builderFromQuery(query, fields);
  const [draft, setDraft] = useState(query);
  const [builder, setBuilder] = useState<BuilderGroup>(initialBuilder ?? { kind: "group", combinator: "AND", children: [], negate: false });
  const [mode, setMode] = useState<"builder" | "text">(initialBuilder && !builderError(initialBuilder, fields) ? "builder" : "text");
  const [previousQuery, setPreviousQuery] = useState(query);
  // Restore history changes without remounting the focused editor or closing help.
  if (previousQuery !== query) {
    setPreviousQuery(query);
    setDraft(query);
    const parsed = builderFromQuery(query, fields);
    if (parsed && !builderError(parsed, fields)) setBuilder(parsed);
    else setMode("text");
  }
  const [help, setHelp] = useState(false);
  const input = useRef<HTMLTextAreaElement>(null);
  const id = useId();
  const result = compileQuery(draft, fields);
  const draftBuilder = builderFromQuery(draft, fields);
  const conversionError = draftBuilder ? builderError(draftBuilder, fields) : "Correct the query text before using the visual builder.";
  const error = mode === "builder" ? builderError(builder, fields) || result.error : result.error;
  const updateBuilder = (value: BuilderGroup) => {
    setBuilder(value);
    setDraft(builderToQuery(value));
  };
  const restore = () => {
    setDraft(query);
    const parsed = builderFromQuery(query, fields);
    if (parsed) setBuilder(parsed);
    else setMode("text");
    setHelp(false);
  };
  const textMode = () => {
    setMode("text");
    requestAnimationFrame(() => input.current?.focus());
  };
  const appliedError = compileQuery(query, queryFields[view]).error;
  const changed = draft !== query;
  const apply = () => {
    if (!error) setWorkspaceQuery(draft.trim());
  };
  return (
    <section className="query-filter" aria-label="Advanced query filter">
      <div className="query-filter-heading">
        <span className="query-filter-label"><Braces size={15} /> Query filter</span>
        <button
          type="button"
          className="query-help-toggle"
          aria-expanded={help}
          aria-controls={`${id}-help`}
          onClick={() => setHelp(!help)}
        >
          <CircleHelp size={14} /> Syntax & fields
        </button>
      </div>
      <div className="query-mode" role="group" aria-label="Query editor mode">
        <button type="button" aria-pressed={mode === "builder"} onClick={() => {
          if (draftBuilder && !conversionError) { setBuilder(draftBuilder); setMode("builder"); }
        }} disabled={mode === "text" && !!conversionError}>Visual builder</button>
        <button type="button" aria-pressed={mode === "text"} onClick={textMode}>Query text</button>
      </div>
      {mode === "text" && conversionError && !result.error && <p className="field-hint">{conversionError}</p>}
      <form
        className={mode === "text" ? `query-input-row${error ? " query-invalid" : ""}` : "query-builder-form"}
        onKeyDown={e => { if (e.key === "Escape") { e.preventDefault(); restore(); } }}
        onSubmit={(e) => {
          e.preventDefault();
          apply();
        }}
      >
        {mode === "builder" ? <>
          <QueryBuilder group={builder} fields={fields} view={view} onChange={updateBuilder} />
          <div className="builder-preview"><span>Query preview</span><code>{draft || "All records in scope"}</code></div>
        </> : <textarea
          ref={input}
          id={id}
          data-query-focus
          rows={2}
          value={draft}
          maxLength={4096}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          aria-label="Filter query"
          aria-invalid={!!error}
          aria-describedby={`${id}-status`}
          placeholder={queryExamples[view][0]}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              apply();
            }
            if (e.key === "Escape") {
              restore();
            }
          }}
        />}
        <button
          className="button button-primary query-apply"
          type="submit"
          disabled={!!error || !changed}
        >
          Apply <ArrowRight size={14} />
        </button>
      </form>
      <div
        className="query-filter-status"
        id={`${id}-status`}
        aria-live="polite"
      >
        <span className={error || appliedError ? "query-error" : ""}>
          {error ||
            appliedError ||
            (changed ? (
              "Unapplied changes · select Apply"
            ) : (
              <>
                <Check size={13} /> {count} {count === 1 ? "result" : "results"}{" "}
                · {query ? "Query applied" : "All records in scope"}
              </>
            ))}
        </span>
        {(draft || query) && (
          <button
            type="button"
            onClick={() => {
              setDraft("");
              setBuilder({ kind: "group", combinator: "AND", children: [], negate: false });
              setWorkspaceQuery("");
            }}
          >
            <X size={13} /> Clear
          </button>
        )}
      </div>
      {appliedError && (
        <p className="query-error">
          The URL query is invalid. Correct it to show results.
        </p>
      )}
      {help && (
        <div className="query-help" id={`${id}-help`}>
          <p>
            <code>field:value</code> contains · <code>=</code> exact ·{" "}
            <code>!=</code> excludes · <code>&gt; &gt;= &lt; &lt;=</code>{" "}
            numbers/dates · <code>field:*</code> has a value
          </p>
          <p>
            Combine with <code>AND OR NOT</code> and parentheses. NOT binds
            first, then AND, then OR. Spaces imply AND. Quote phrases and URLs.{" "}
            <code>*</code> matches any characters. Text ignores case. Empty
            queries show all records in scope.
          </p>
          <div className="query-field-list" aria-label="Available fields">
            {Object.entries(queryFields[view]).map(([field, type]) => (
              <button
                type="button"
                key={field}
                title={`${type} field`}
                onClick={() => {
                  setDraft(
                    `${draft}${draft && !/\s$/.test(draft) ? " AND " : ""}${field}:`,
                  );
                  textMode();
                }}
              >
                <code>{field}</code>
                <span>{type}</span>
              </button>
            ))}
          </div>
          <div className="query-examples">
            <span>Try a query</span>
            {queryExamples[view].map((example) => (
              <button
                type="button"
                key={example}
                onClick={() => {
                  setDraft(example);
                  const parsed = builderFromQuery(example, fields);
                  if (parsed) { setBuilder(parsed); setMode("builder"); }
                }}
              >
                <code>{example}</code>
                <ArrowRight size={13} />
              </button>
            ))}
          </div>
          <p>
            Filters search loaded workspace observations. They do not run
            scanners or change assessment coverage. Dates use ISO format, for
            example <code>2026-01-01</code>.
          </p>
        </div>
      )}
    </section>
  );
}
