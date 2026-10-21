/** A bounded, data-only query language. Never evaluates JavaScript or user regexes. */
export type QueryValue = string | number | boolean | undefined | null;
export type QueryDocument = Record<string, QueryValue | QueryValue[]>;
export type QueryFields = Record<
  string,
  "text" | "number" | "boolean" | "date"
>;
type Token = { text: string; at: number; quoted?: boolean };
type Predicate = (document: QueryDocument) => boolean;
export type QueryExpression =
  | { kind: "rule"; field: string; operator: string; value: string }
  | { kind: "search"; value: string }
  | { kind: "not"; child: QueryExpression }
  | { kind: "group"; combinator: "AND" | "OR"; children: QueryExpression[] };
type Parsed = { matches: Predicate; expression: QueryExpression };
export type QueryResult = { matches: Predicate; error: string | null; expression?: QueryExpression };

export function compileQuery(source: string, fields: QueryFields): QueryResult {
  const fail = (message: string, at: number): never => {
    throw new Error(`${message} (column ${at + 1}).`);
  };
  try {
    if (source.length > 4096) fail("Query exceeds 4,096 characters", 4096);
    const tokens: Token[] = [];
    let i = 0;
    while (i < source.length) {
      if (/\s/.test(source[i])) {
        i++;
        continue;
      }
      const at = i;
      if (source[i] === '"' || source[i] === "'") {
        const quote = source[i++];
        let text = "";
        while (i < source.length && source[i] !== quote) {
          if (source[i] === "\\") {
            i++;
            if (i === source.length) fail("Unfinished escape", i - 1);
          }
          text += source[i++];
        }
        if (i === source.length) fail("Unclosed quote", at);
        i++;
        tokens.push({ text, at, quoted: true });
      } else if (/[():=<>!]/.test(source[i])) {
        let text = source[i++];
        if (/[=<>!]/.test(text) && source[i] === "=") text += source[i++];
        if (text === "==") fail("Use = for exact equality", at);
        tokens.push({ text, at });
      } else {
        while (i < source.length && !/[\s():=<>!"']/.test(source[i])) i++;
        tokens.push({ text: source.slice(at, i), at });
      }
      if (tokens.length > 512) fail("Query has too many terms", at);
    }
    let cursor = 0;
    const peek = (text: string) =>
      !tokens[cursor]?.quoted && tokens[cursor]?.text.toUpperCase() === text;
    const take = () =>
      tokens[cursor++] ?? fail("Expected a value", source.length);
    const values = (doc: QueryDocument, field: string) => {
      const value = doc[field];
      return (Array.isArray(value) ? value : [value]).filter(
        (v) => v !== undefined && v !== null && v !== "",
      );
    };
    const textMatch = (value: QueryValue, term: string, exact: boolean) => {
      const actual = String(value).toLowerCase(),
        expected = term.toLowerCase();
      if (!expected.includes("*"))
        return exact ? actual === expected : actual.includes(expected);
      // Literal segments with wildcard gaps; no user-controlled regular expressions.
      const parts = expected.split("*");
      let offset = 0;
      for (let index = 0; index < parts.length; index++) {
        const part = parts[index];
        if (!part) continue;
        const found = actual.indexOf(part, offset);
        if (found < 0 || (index === 0 && found !== 0)) return false;
        offset = found + part.length;
      }
      return expected.endsWith("*") || actual.endsWith(parts[parts.length - 1]);
    };
    const atom = (depth: number): Parsed => {
      if (depth > 32)
        fail("Nesting exceeds 32 levels", tokens[cursor]?.at ?? source.length);
      if (peek("NOT")) {
        take();
        const child = atom(depth + 1);
        return { matches: (doc) => !child.matches(doc), expression: { kind: "not", child: child.expression } };
      }
      if (peek("(")) {
        take();
        const inner = or(depth + 1);
        if (!peek(")"))
          fail(
            "Expected closing parenthesis",
            tokens[cursor]?.at ?? source.length,
          );
        take();
        return inner;
      }
      const token = take();
      if (
        !token.quoted &&
        [")", "AND", "OR", ":", "=", "!=", "<", ">", "<=", ">=", "!"].includes(
          token.text.toUpperCase(),
        )
      )
        fail("Expected a field or search term", token.at);
      const operator = tokens[cursor];
      if (
        !operator ||
        operator.quoted ||
        ![":", "=", "!=", "<", ">", "<=", ">="].includes(operator.text)
      ) {
        return {
          matches: (doc) => Object.keys(fields).some((field) => values(doc, field).some((v) => textMatch(v, token.text, false))),
          expression: { kind: "search", value: token.text },
        };
      }
      take();
      const field = token.text.toLowerCase();
      if (!Object.hasOwn(fields, field))
        fail(`Unknown field “${token.text}”`, token.at);
      const term = take();
      if (
        !term.quoted &&
        [
          "(",
          ")",
          "AND",
          "OR",
          "NOT",
          ":",
          "=",
          "!=",
          "<",
          ">",
          "<=",
          ">=",
        ].includes(term.text.toUpperCase())
      )
        fail(
          "Expected a value; quote values containing spaces or punctuation",
          term.at,
        );
      const type = fields[field],
        op = operator.text;
      if (["<", ">", "<=", ">="].includes(op) && term.text === "*")
        fail("Range comparisons require a number or date", term.at);
      if (
        ["<", ">", "<=", ">="].includes(op) &&
        type !== "number" &&
        type !== "date"
      )
        fail(
          `Field “${field}” does not support range comparisons`,
          operator.at,
        );
      if (
        term.text !== "*" &&
        type === "number" &&
        (!term.text.trim() || !Number.isFinite(Number(term.text)))
      )
        fail(`Expected a number for “${field}”`, term.at);
      if (
        term.text !== "*" &&
        type === "boolean" &&
        !["true", "false"].includes(term.text.toLowerCase())
      )
        fail(`Expected true or false for “${field}”`, term.at);
      if (
        term.text !== "*" &&
        type === "date" &&
        !Number.isFinite(Date.parse(term.text))
      )
        fail(`Expected an ISO date for “${field}”`, term.at);
      const match: Predicate = (doc) => {
        const entries = values(doc, field);
        const result =
          term.text === "*"
            ? entries.length > 0
            : entries.some((value) => {
                if (type === "text" || type === "boolean")
                  return textMatch(value, term.text, op !== ":");
                const actual =
                  type === "date" ? Date.parse(String(value)) : Number(value);
                const expected =
                  type === "date" ? Date.parse(term.text) : Number(term.text);
                if (!Number.isFinite(actual)) return false;
                if (op === ">") return actual > expected;
                if (op === "<") return actual < expected;
                if (op === ">=") return actual >= expected;
                if (op === "<=") return actual <= expected;
                return actual === expected;
              });
        return op === "!=" ? !result : result;
      };
      return { matches: match, expression: { kind: "rule", field, operator: op, value: term.text } };
    };
    const and = (depth: number): Parsed => {
      const children = [atom(depth)];
      while (cursor < tokens.length && !peek(")") && !peek("OR")) {
        if (peek("AND")) take();
        children.push(atom(depth));
      }
      return children.length === 1 ? children[0] : {
        matches: (doc) => children.every((child) => child.matches(doc)),
        expression: { kind: "group", combinator: "AND", children: children.map(child => child.expression) },
      };
    };
    const or = (depth: number): Parsed => {
      const children = [and(depth)];
      while (peek("OR")) {
        take();
        children.push(and(depth));
      }
      return children.length === 1 ? children[0] : {
        matches: (doc) => children.some((child) => child.matches(doc)),
        expression: { kind: "group", combinator: "OR", children: children.map(child => child.expression) },
      };
    };
    const parsed: Parsed = tokens.length ? or(0) : { matches: () => true, expression: { kind: "group", combinator: "AND", children: [] } };
    if (cursor !== tokens.length) fail("Unexpected token", tokens[cursor].at);
    return { ...parsed, error: null };
  } catch (error) {
    return {
      matches: () => false,
      error: error instanceof Error ? error.message : "Invalid query.",
    };
  }
}


export type BuilderRule = { kind: "rule"; field: string; operator: string; value: string; negate: boolean };
export type BuilderGroup = { kind: "group"; combinator: "AND" | "OR"; children: BuilderNode[]; negate: boolean };
export type BuilderNode = BuilderRule | BuilderGroup;
export const anyField = "__any";
export const fieldLabel = (field: string) => field === anyField ? "Any field" : ({ cve: "CVE", cwe: "CWE", cvss: "CVSS", ip: "IP address", url: "URL", tech: "Technology", at: "Event time" }[field] ?? field.replaceAll("_", " ").replace(/^./, c => c.toUpperCase()));

export function newRule(fields: QueryFields): BuilderRule {
  const field = Object.keys(fields)[0];
  return { kind: "rule", field, operator: fields[field] === "text" ? ":" : "=", value: "", negate: false };
}
export function newGroup(fields: QueryFields): BuilderGroup {
  return { kind: "group", combinator: "AND", children: [newRule(fields)], negate: false };
}
function fromExpression(node: QueryExpression): BuilderNode {
  if (node.kind === "not") {
    const child = fromExpression(node.child);
    return { ...child, negate: !child.negate };
  }
  if (node.kind === "group") return { ...node, negate: false, children: node.children.map(fromExpression) };
  if (node.kind === "search") return { kind: "rule", field: anyField, operator: ":", value: node.value, negate: false };
  return { ...node, negate: false };
}
export function builderFromQuery(source: string, fields: QueryFields): BuilderGroup | null {
  const parsed = compileQuery(source, fields);
  if (!parsed.expression || parsed.error) return null;
  const node = fromExpression(parsed.expression);
  return node.kind === "group" ? node : { kind: "group", combinator: "AND", children: [node], negate: false };
}

// Quote every value so user input cannot introduce operators or change grouping.
export function builderToQuery(node: BuilderNode): string {
  let source: string;
  if (node.kind === "group") {
    if (!node.children.length) return "";
    source = node.children.map(builderToQuery).join(` ${node.combinator} `);
    source = `(${source})`;
  } else {
    const quoted = '"' + node.value.replaceAll('\\', '\\\\').replaceAll('"', '\\"') + '"';
    source = node.field === anyField ? quoted : `${node.field}${node.operator}${quoted}`;
  }
  return node.negate ? `NOT ${source}` : source;
}
export function builderError(node: BuilderNode, fields: QueryFields, depth = 0): string | null {
  if (depth > 12) return "Use Query text for groups deeper than 12 levels.";
  if (node.kind === "group") {
    if (!node.children.length && depth > 0) return "Add a condition to the empty group or remove it.";
    if (!node.children.length && node.negate) return "Add a condition before excluding a group.";
    for (const child of node.children) { const error = builderError(child, fields, depth + 1); if (error) return error; }
  } else if (!node.value.trim()) return `Enter a value for ${fieldLabel(node.field)}.`;
  return compileQuery(builderToQuery(node), fields).error;
}
export function ruleOperators(type: QueryFields[string] | "search") {
  if (type === "search") return [{ value: ":", label: "Contains" }];
  const ops = type === "text" ? [{ value: ":", label: "Contains" }] : [];
  ops.push({ value: "=", label: "Equals" }, { value: "!=", label: "Does not equal" });
  if (type === "number" || type === "date") ops.push(
    { value: ">", label: type === "date" ? "After" : "Greater than" },
    { value: ">=", label: type === "date" ? "On or after" : "At least" },
    { value: "<", label: type === "date" ? "Before" : "Less than" },
    { value: "<=", label: type === "date" ? "On or before" : "At most" },
  );
  ops.push({ value: "exists", label: "Has a value" }, { value: "missing", label: "Has no value" });
  return ops;
}
