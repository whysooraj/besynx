let socket = null;
const localCookieWrites = new Set();
let isConnecting = false;
let reconnectDelay = 1000;
const MAX_RECONNECT_DELAY = 30000;
const pendingAcks = new Set();

function connect() {
  if (isConnecting || (socket && (socket.readyState === WebSocket.CONNECTING || socket.readyState === WebSocket.OPEN))) return;
  isConnecting = true;

  chrome.storage.local.get({ token: '' }, (data) => {
    if (!data.token) {
      console.warn("besynx: Authentication token not set in extension options.");
      isConnecting = false;
      return;
    }
    console.log("besynx: connecting to daemon...");
    socket = new WebSocket(`ws://127.0.0.1:9098/sync?token=${encodeURIComponent(data.token)}`);

    socket.onopen = async () => {
      console.log("besynx: connected to daemon");
      isConnecting = false;
      reconnectDelay = 1000; // Reset backoff
      pendingAcks.clear();
      socket.send(JSON.stringify({ event: "hello", device: "extension" }));
      await flushQueue();
    };

    socket.onmessage = async (event) => {
      console.log("besynx: from daemon:", event.data);
      try {
        const msg = JSON.parse(event.data);
        if (msg.ack) {
          await dequeueItem(msg.ack);
        } else if (msg.event === "cookie_changed") {
          const normalizedDomain = msg.domain.startsWith(".") ? msg.domain.slice(1) : msg.domain;
          const writeKey = `${normalizedDomain}|${msg.name}|${msg.value}|${msg.path}`;
          localCookieWrites.add(writeKey);

          const url = (msg.secure ? "https://" : "http://") + normalizedDomain + msg.path;

          const details = {
            url: url,
            name: msg.name,
            value: msg.value,
            domain: msg.domain,
            path: msg.path,
            secure: msg.secure,
            httpOnly: msg.http_only,
          };

          if (msg.same_site) {
            if (["no_restriction", "lax", "strict", "unspecified"].includes(msg.same_site)) {
              details.sameSite = msg.same_site;
            }
          }

          if (msg.expiration_date !== null && msg.expiration_date !== undefined) {
            details.expirationDate = msg.expiration_date;
          }

          chrome.cookies.set(details, (cookie) => {
            if (chrome.runtime.lastError) {
              console.error("besynx: failed to set cookie:", chrome.runtime.lastError.message);
              localCookieWrites.delete(writeKey);
            }
          });
        } else if (msg.event === "cookie_deleted") {
          const normalizedDomain = msg.domain.startsWith(".") ? msg.domain.slice(1) : msg.domain;
          const writeKey = `${normalizedDomain}|${msg.name}|DELETED|${msg.path}`;
          localCookieWrites.add(writeKey);

          const url = (msg.secure ? "https://" : "http://") + normalizedDomain + msg.path;
          chrome.cookies.remove({ url: url, name: msg.name }, () => {
            if (chrome.runtime.lastError) {
              console.error("besynx: failed to remove cookie:", chrome.runtime.lastError.message);
              localCookieWrites.delete(writeKey);
            }
          });
        }
      } catch (e) {
        console.error("besynx: failed to parse message", e);
      }
    };

    socket.onclose = () => {
      console.log("besynx: connection closed");
      socket = null;
      isConnecting = false;
      pendingAcks.clear();
      scheduleReconnect();
    };

    socket.onerror = (err) => {
      console.error("besynx: socket error:", err);
      socket = null;
      isConnecting = false;
    };
  });
}

function scheduleReconnect() {
  setTimeout(() => {
    reconnectDelay = Math.min(reconnectDelay * 2, MAX_RECONNECT_DELAY);
    connect();
  }, reconnectDelay);
}

let queuePromise = Promise.resolve();
async function fnQueueItem(item) {
  queuePromise = queuePromise.then(async () => {
    const data = await chrome.storage.local.get({ queue: [] });
    data.queue.push(item);
    await chrome.storage.local.set({ queue: data.queue });
  });
  return queuePromise;
}

async function dequeueItem(id) {
  queuePromise = queuePromise.then(async () => {
    pendingAcks.delete(id);
    const data = await chrome.storage.local.get({ queue: [] });
    const newQueue = data.queue.filter(item => item.id !== id);
    await chrome.storage.local.set({ queue: newQueue });
  });
  return queuePromise;
}

async function flushQueue() {
  queuePromise = queuePromise.then(async () => {
    if (!socket || socket.readyState !== WebSocket.OPEN) return;
    const data = await chrome.storage.local.get({ queue: [] });
    if (data.queue.length === 0) return;

    console.log(`besynx: flushing ${data.queue.length} items`);
    for (const item of data.queue) {
      if (!pendingAcks.has(item.id)) {
        pendingAcks.add(item.id);
        socket.send(JSON.stringify(item));
      }
    }
  });
  return queuePromise;
}

chrome.history.onVisited.addListener(async (historyItem) => {
  console.log("besynx: visited:", historyItem.url);
  const item = {
    id: self.crypto.randomUUID(),
    event: "visited",
    url: historyItem.url,
    title: historyItem.title || "",
    timestamp: historyItem.lastVisitTime || Date.now()
  };

  await fnQueueItem(item);
  connect();
  await flushQueue();
});

chrome.cookies.onChanged.addListener(async (changeInfo) => {
  const cookie = changeInfo.cookie;
  const normalizedDomain = cookie.domain.startsWith(".") ? cookie.domain.slice(1) : cookie.domain;
  
  if (changeInfo.removed) {
    const writeKey = `${normalizedDomain}|${cookie.name}|DELETED|${cookie.path}`;
    if (localCookieWrites.has(writeKey)) {
      localCookieWrites.delete(writeKey);
      return;
    }

    console.log("besynx: cookie deleted:", cookie.name);
    const item = {
      id: self.crypto.randomUUID(),
      event: "cookie_deleted",
      domain: cookie.domain,
      name: cookie.name,
      path: cookie.path,
      secure: cookie.secure,
      timestamp: Date.now()
    };
    await fnQueueItem(item);
    connect();
    await flushQueue();
    return;
  }

  if (changeInfo.cause === "explicit" || changeInfo.cause === "overwrite") {
    const writeKey = `${normalizedDomain}|${cookie.name}|${cookie.value}|${cookie.path}`;
    if (localCookieWrites.has(writeKey)) {
      localCookieWrites.delete(writeKey);
      return;
    }

    console.log("besynx: cookie changed:", cookie.name);
    const item = {
      id: self.crypto.randomUUID(),
      event: "cookie_changed",
      domain: cookie.domain,
      name: cookie.name,
      value: cookie.value,
      path: cookie.path,
      secure: cookie.secure,
      http_only: cookie.httpOnly,
      expiration_date: cookie.expirationDate ? Math.floor(cookie.expirationDate) : null,
      same_site: cookie.sameSite || "no_restriction",
      timestamp: Date.now()
    };

    await fnQueueItem(item);
    connect();
    await flushQueue();
  }
});

// Initial connection attempt
connect();
