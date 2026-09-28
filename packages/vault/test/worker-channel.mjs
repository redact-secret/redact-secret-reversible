// An in-memory stand-in for a dedicated Worker's message channel, for the
// Worker-mode unit tests. `port` is the page's handle (what `new Worker()`
// returns); `scope` is the Worker's global scope (the host's `target`).
// Every message is copied with `structuredClone` and delivered on a later
// task, as the platform does: nothing is shared by reference, and functions
// fail to clone exactly as they would across a real thread boundary.

function endpoint() {
  const listeners = { message: [], error: [], messageerror: [] };
  const self = {
    peer: undefined,
    terminated: false,
    posted: [],
    postMessage(message) {
      const data = structuredClone(message);
      self.posted.push(data);
      const peer = self.peer;
      setTimeout(() => {
        if (self.terminated || peer.terminated) return;
        for (const listener of [...peer.listeners.message]) listener({ data });
      }, 0);
    },
    addEventListener(type, listener) {
      listeners[type].push(listener);
    },
    removeEventListener(type, listener) {
      const list = listeners[type];
      const index = list.indexOf(listener);
      if (index >= 0) list.splice(index, 1);
    },
    terminate() {
      self.terminated = true;
    },
    listeners,
  };
  return self;
}

export function channel() {
  const port = endpoint();
  const scope = endpoint();
  port.peer = scope;
  scope.peer = port;
  return { port, scope };
}

/** Sends one raw message from the page side, bypassing the client, and resolves with the matching `vault-response`. */
export function rawRequest(port, message, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      port.removeEventListener("message", onMessage);
      reject(new Error(`no reply to raw request ${message.id}`));
    }, timeoutMs);
    const onMessage = (event) => {
      const data = event.data;
      if (data && data.kind === "vault-response" && data.id === message.id) {
        clearTimeout(timer);
        port.removeEventListener("message", onMessage);
        resolve(data);
      }
    };
    port.addEventListener("message", onMessage);
    port.postMessage(message);
  });
}

/** Resolves with the host's first handshake message (`vault-ready` or `vault-init-failed`). */
export function nextHandshake(port) {
  return new Promise((resolve) => {
    const onMessage = (event) => {
      const kind = event.data && event.data.kind;
      if (kind === "vault-ready" || kind === "vault-init-failed") {
        port.removeEventListener("message", onMessage);
        resolve(event.data);
      }
    };
    port.addEventListener("message", onMessage);
  });
}
