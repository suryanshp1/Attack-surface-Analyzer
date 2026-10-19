export type ConnectionState =
  | "connecting"
  | "live"
  | "reconnecting"
  | "offline";

type Stream = {
  onopen: ((event: Event) => unknown) | null;
  onmessage: ((event: MessageEvent) => unknown) | null;
  onerror: ((event: Event) => unknown) | null;
  close: () => void;
};
type Options<T> = {
  snapshot: (value: T) => void;
  connection: (value: ConnectionState) => void;
  error: (message: string) => void;
  unauthorized: () => void;
  fetchState: (signal: AbortSignal) => Promise<Response>;
  openStream: () => Stream;
  visible: () => boolean;
};

// Polls and mutation refreshes share one request loop. A stream snapshot
// supersedes any poll that began before it, so a late poll cannot roll state back.
export function createWorkspaceSync<T>(options: Options<T>) {
  let stopped = false,
    authorized = false,
    connected = false;
  let generation = 0,
    attempts = 0,
    queued = false;
  let stream: Stream | null = null;
  let inFlight: Promise<void> | null = null;
  let controller: AbortController | null = null;
  let reconnect: ReturnType<typeof setTimeout> | undefined;

  function disconnect() {
    connected = false;
    stream?.close();
    stream = null;
    clearTimeout(reconnect);
    reconnect = undefined;
  }
  function connect() {
    if (stopped || !authorized || !options.visible() || stream) return;
    const current = options.openStream();
    stream = current;
    current.onopen = () => {
      if (stream !== current || stopped) return;
      connected = true;
      attempts = 0;
      options.connection("live");
    };
    current.onmessage = (event) => {
      if (stream !== current || stopped) return;
      try {
        const value = JSON.parse(event.data) as T;
        generation++;
        options.snapshot(value);
        options.error("");
      } catch {
        current.onerror?.(new Event("error"));
      }
    };
    current.onerror = () => {
      if (stream !== current || stopped) return;
      disconnect();
      options.connection("reconnecting");
      reconnect = setTimeout(
        connect,
        Math.min(30000, 1000 * 2 ** Math.min(attempts++, 5)),
      );
    };
  }
  async function load() {
    do {
      queued = false;
      const started = generation;
      controller = new AbortController();
      const request = controller;
      const timeout = setTimeout(() => request.abort(), 15000);
      try {
        const response = await options.fetchState(controller.signal);
        if (stopped) return;
        if (response.status === 401) {
          authorized = false;
          queued = false;
          disconnect();
          options.unauthorized();
          return;
        }
        const value = await response.json();
        if (stopped) return;
        if (!response.ok)
          throw new Error(value.error || "Workspace update failed");
        authorized = true;
        if (started === generation) options.snapshot(value as T);
        options.error("");
        if (!connected) options.connection("reconnecting");
        connect();
      } catch (error) {
        if (stopped) return;
        options.error(
          error instanceof Error ? error.message : "Workspace update failed",
        );
        if (!connected) options.connection("offline");
      } finally {
        clearTimeout(timeout);
      }
    } while (queued && !stopped);
  }
  function refresh(): Promise<void> {
    if (stopped) return Promise.resolve();
    if (inFlight) {
      queued = true;
      return inFlight;
    }
    inFlight = load().finally(() => {
      inFlight = null;
    });
    return inFlight;
  }
  const poll = setInterval(() => {
    if (authorized && !connected && options.visible() && !inFlight)
      void refresh();
  }, 8000);
  return {
    refresh,
    visibilityChanged() {
      if (!options.visible()) {
        disconnect();
        return;
      }
      if (authorized) {
        void refresh();
        connect();
      }
    },
    stop() {
      stopped = true;
      queued = false;
      clearInterval(poll);
      disconnect();
      controller?.abort();
    },
  };
}
