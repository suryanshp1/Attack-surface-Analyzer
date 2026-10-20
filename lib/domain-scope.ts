// UI scope matching uses hostname boundaries, never URL substring matching.
export function hostInScope(host: string, scope: string) {
  if (scope === "all") return true;
  const normalized = host.toLowerCase().replace(/\.$/, "");
  const root = scope.toLowerCase().replace(/\.$/, "");
  return normalized === root || normalized.endsWith(`.${root}`);
}

export function urlInScope(url: string, scope: string) {
  try {
    return hostInScope(new URL(url).hostname, scope);
  } catch {
    return false;
  }
}
