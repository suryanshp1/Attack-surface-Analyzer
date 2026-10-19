import test from "node:test";
import assert from "node:assert/strict";
import { createWorkspaceSync } from "../lib/workspace-sync.ts";

const flush = () => new Promise(setImmediate);
function fixture(t, fetchState) {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  const snapshots = [],
    streams = [],
    connections = [],
    errors = [];
  let visible = true,
    unauthorized = 0,
    calls = 0;
  const sync = createWorkspaceSync({
    snapshot: (value) => snapshots.push(value),
    connection: (value) => connections.push(value),
    error: (value) => errors.push(value),
    unauthorized: () => unauthorized++,
    fetchState: (signal) => {
      calls++;
      return fetchState(signal);
    },
    visible: () => visible,
    openStream() {
      const stream = {
        onopen: null,
        onmessage: null,
        onerror: null,
        closed: false,
        close() {
          this.closed = true;
        },
      };
      streams.push(stream);
      return stream;
    },
  });
  t.after(() => sync.stop());
  return {
    sync,
    snapshots,
    streams,
    connections,
    errors,
    hide() {
      visible = false;
      sync.visibilityChanged();
    },
    show() {
      visible = true;
      sync.visibilityChanged();
    },
    get calls() {
      return calls;
    },
    get unauthorized() {
      return unauthorized;
    },
  };
}
const response = (value) => Response.json(value);

test("healthy streaming suppresses polling; errors reconnect and enable fallback", async (t) => {
  const f = fixture(t, async () => response({ version: 1 }));
  await f.sync.refresh();
  f.streams[0].onopen(new Event("open"));
  t.mock.timers.tick(16000);
  await flush();
  assert.equal(f.calls, 1);
  f.streams[0].onerror(new Event("error"));
  assert.equal(f.streams[0].closed, true);
  t.mock.timers.tick(1000);
  await flush();
  assert.equal(f.streams.length, 2);
  t.mock.timers.tick(7000);
  await flush();
  assert.equal(f.calls, 2);
  assert.ok(f.connections.includes("reconnecting"));
});

test("late polling responses cannot overwrite a newer stream snapshot", async (t) => {
  let resolve;
  const f = fixture(t, async () =>
    f.calls === 1
      ? response({ version: 1 })
      : new Promise((r) => {
          resolve = r;
        }),
  );
  await f.sync.refresh();
  f.streams[0].onopen(new Event("open"));
  const pending = f.sync.refresh();
  f.streams[0].onmessage(
    new MessageEvent("message", { data: '{"version":3}' }),
  );
  resolve(response({ version: 2 }));
  await pending;
  assert.deepEqual(f.snapshots.at(-1), { version: 3 });
});

test("refreshes serialize and a queued mutation refresh fetches again", async (t) => {
  let resolve,
    active = 0,
    peak = 0;
  const f = fixture(t, async () => {
    active++;
    peak = Math.max(peak, active);
    if (f.calls === 1)
      await new Promise((r) => {
        resolve = r;
      });
    active--;
    return response({ version: f.calls });
  });
  const first = f.sync.refresh();
  const second = f.sync.refresh();
  assert.equal(f.calls, 1);
  resolve();
  await Promise.all([first, second]);
  assert.equal(peak, 1);
  assert.equal(f.calls, 2);
});

test("hidden tabs stop streaming and polling; visible tabs refresh and reconnect", async (t) => {
  const f = fixture(t, async () => response({ version: 1 }));
  await f.sync.refresh();
  f.hide();
  t.mock.timers.tick(24000);
  await flush();
  assert.equal(f.calls, 1);
  assert.equal(f.streams[0].closed, true);
  f.show();
  await flush();
  assert.equal(f.calls, 2);
  assert.equal(f.streams.length, 2);
});

test("revoked session stops updates until an explicit successful refresh", async (t) => {
  const f = fixture(t, async () =>
    f.calls === 1
      ? response({ version: 1 })
      : new Response("{}", { status: 401 }),
  );
  await f.sync.refresh();
  await f.sync.refresh();
  assert.equal(f.unauthorized, 1);
  assert.equal(f.streams[0].closed, true);
  t.mock.timers.tick(32000);
  await flush();
  assert.equal(f.calls, 2);
});

test("unavailable snapshots preserve existing observations and report offline", async (t) => {
  const f = fixture(t, async () => {
    if (f.calls === 1) return response({ version: 1 });
    throw new Error("Disconnected");
  });
  await f.sync.refresh();
  await f.sync.refresh();
  assert.deepEqual(f.snapshots, [{ version: 1 }]);
  assert.equal(f.connections.at(-1), "offline");
  assert.equal(f.errors.at(-1), "Disconnected");
});

test("stopping aborts a pending request and suppresses later callbacks", async (t) => {
  let resolve, signal;
  const f = fixture(t, (value) => {
    signal = value;
    return new Promise((r) => {
      resolve = r;
    });
  });
  const pending = f.sync.refresh();
  f.sync.stop();
  assert.equal(signal.aborted, true);
  resolve(response({ version: 1 }));
  await pending;
  assert.deepEqual(f.snapshots, []);
  assert.equal(f.streams.length, 0);
});

test("stalled snapshot requests time out and allow a later refresh", async (t) => {
  let signal;
  const f = fixture(t, (value) => {
    signal = value;
    if (f.calls > 1) return Promise.resolve(response({ version: 2 }));
    return new Promise((_, reject) =>
      value.addEventListener(
        "abort",
        () => reject(new Error("Request timed out")),
        { once: true },
      ),
    );
  });
  const pending = f.sync.refresh();
  t.mock.timers.tick(15000);
  await pending;
  assert.equal(signal.aborted, true);
  assert.equal(f.connections.at(-1), "offline");
  await f.sync.refresh();
  assert.deepEqual(f.snapshots.at(-1), { version: 2 });
});
