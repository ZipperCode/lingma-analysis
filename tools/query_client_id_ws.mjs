#!/usr/bin/env node

import process from "node:process";

function encodeLsp(message) {
  const body = JSON.stringify(message);
  return `Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`;
}

function parseLspFrames(buffer) {
  const messages = [];
  const marker = "\r\n\r\n";
  let offset = 0;

  while (offset < buffer.length) {
    const headerEnd = buffer.indexOf(marker, offset);
    if (headerEnd < 0) {
      break;
    }

    const header = buffer.slice(offset, headerEnd);
    const match = header.match(/content-length:\s*(\d+)/i);
    if (!match) {
      break;
    }

    const contentLength = Number(match[1]);
    const bodyStart = headerEnd + marker.length;
    const bodyEnd = bodyStart + contentLength;
    if (bodyEnd > buffer.length) {
      break;
    }

    const raw = buffer.slice(bodyStart, bodyEnd);
    try {
      messages.push(JSON.parse(raw));
    } catch (error) {
      messages.push({ parseError: String(error), raw });
    }
    offset = bodyEnd;
  }

  return messages;
}

function deepDecode(value) {
  let current = value;
  for (let i = 0; i < 6; i += 1) {
    try {
      const next = decodeURIComponent(current);
      if (next === current) {
        break;
      }
      current = next;
    } catch {
      break;
    }
  }
  return current;
}

function collectUrls(obj, results = new Set()) {
  if (typeof obj === "string") {
    const matches = obj.match(/https?:\/\/[^\s"'<>]+/g);
    if (matches) {
      for (const match of matches) {
        results.add(match);
      }
    }
    return results;
  }

  if (Array.isArray(obj)) {
    for (const item of obj) {
      collectUrls(item, results);
    }
    return results;
  }

  if (obj && typeof obj === "object") {
    for (const value of Object.values(obj)) {
      collectUrls(value, results);
    }
  }
  return results;
}

function printUrlAnalysis(url) {
  const decoded = deepDecode(url);
  console.log(`URL: ${url}`);
  if (decoded !== url) {
    console.log(`Decoded: ${decoded}`);
  }

  const candidates = [url, decoded];
  for (const candidate of candidates) {
    try {
      const parsed = new URL(candidate);
      const clientId = parsed.searchParams.get("client_id");
      if (clientId) {
        console.log(`CLIENT_ID: ${clientId}`);
      }

      const nested = parsed.searchParams.get("oauth_callback");
      if (nested) {
        console.log(`oauth_callback: ${deepDecode(nested)}`);
      }
    } catch {
      // ignore parse failures
    }
  }
  console.log("");
}

async function main() {
  const wsUrl = process.argv[2] || "ws://127.0.0.1:37010";
  const methods = [
    ["initialize", {
      processId: null,
      clientInfo: { name: "client-id-probe", version: "1.0" },
      rootUri: "file:///tmp/lingma-analysis",
      capabilities: {},
      workspaceFolders: [{ uri: "file:///tmp/lingma-analysis", name: "workspace" }],
    }],
    ["auth/status", {}],
    ["auth/profile/getUrl", {}],
    ["auth/login", {}],
  ];

  const ws = new WebSocket(wsUrl);
  const messages = [];

  const done = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      ws.close();
      resolve();
    }, 15000);

    ws.onopen = () => {
      let id = 1;
      for (const [method, params] of methods) {
        ws.send(encodeLsp({
          jsonrpc: "2.0",
          id,
          method,
          params,
        }));
        id += 1;
      }
    };

    ws.onmessage = (event) => {
      const data = typeof event.data === "string" ? event.data : event.data.toString("utf8");
      messages.push(...parseLspFrames(data));
    };

    ws.onerror = (event) => {
      clearTimeout(timeout);
      reject(new Error(`WebSocket error: ${event?.message || "unknown"}`));
    };

    ws.onclose = () => {
      clearTimeout(timeout);
      resolve();
    };
  });

  await done;

  const payload = { wsUrl, messages };
  console.log(JSON.stringify(payload, null, 2));
  console.log("\n=== URL ANALYSIS ===");

  const urls = [...collectUrls(payload)];
  if (urls.length === 0) {
    console.log("No URLs found.");
    return;
  }
  for (const url of urls) {
    printUrlAnalysis(url);
  }
}

main().catch((error) => {
  console.error(error.stack || String(error));
  process.exit(1);
});
