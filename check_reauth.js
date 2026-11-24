#!/usr/bin/env node
/**
 * Verify that the TrueLayer re-auth link fallback is still present.
 *
 * The plugin must not use a re-auth link on the normal sync path, but the
 * fallback is still needed when a consent genuinely expires. This script
 * checks both the source and the behaviour of the installed plugin code.
 *
 * Run with: node check_reauth.js
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const root = __dirname;
const pluginPath = path.join(root, "truelayer_plugin.py");
const failures = [];

function check(name, fn) {
  try {
    fn();
    console.log(`ok   - ${name}`);
  } catch (error) {
    failures.push(name);
    console.error(`FAIL - ${name}: ${error.message}`);
  }
}

function read(file) {
  if (!fs.existsSync(file)) throw new Error(`missing file: ${file}`);
  return fs.readFileSync(file, "utf8");
}

function section(source, start, end) {
  const from = source.indexOf(start);
  if (from === -1) throw new Error(`missing section start: ${start}`);
  const to = end ? source.indexOf(end, from + start.length) : source.length;
  if (to === -1) throw new Error(`missing section end: ${end}`);
  return source.slice(from, to);
}

function expect(condition, message) {
  if (!condition) throw new Error(message);
}

check("plugin source exposes build_reauth_url", () => {
  const source = read(pluginPath);
  expect(source.includes("def build_reauth_url("), "build_reauth_url() was removed");
  expect(source.includes("/v1/reauthuri"), "the /v1/reauthuri call was removed");
});

check("oauth_url still uses the reauth link with a full-auth fallback", () => {
  const source = read(pluginPath);
  const body = section(source, "def oauth_url(", "def oauth_exchange(");
  expect(body.includes("build_reauth_url("), "oauth_url no longer tries the reauth link");
  expect(body.includes("(400, 401, 404)"), "oauth_url lost the reauth fallback statuses");
  expect(body.includes("build_auth_url("), "oauth_url lost the full-auth fallback");

  const sync = section(source, "def sync(");
  expect(!sync.includes("build_reauth_url("), "normal sync must never ask for a reauth link");
});

check("reauth link behaviour works (Python runtime check)", () => {
  const python = `
import sys, types
from unittest.mock import patch
sys.path.insert(0, ${JSON.stringify(root)})
import truelayer_plugin as p

params = {"redirect_uri": "https://securo.example/cb", "state": "s1"}
ctx = types.SimpleNamespace(
    config={"client_id": "app-123"},
    secrets={"refresh_token": "refresh-1"},
)
calls = []

def fake_request(url, **kwargs):
    calls.append((url, kwargs))
    return {"result": "https://auth.truelayer.com/reauth?x=1", "success": True}

with patch.object(p, "_request", side_effect=fake_request):
    result = p.plugin.oauth_url(params, ctx)
assert result == {"url": "https://auth.truelayer.com/reauth?x=1"}, result
assert len(calls) == 1 and calls[0][0].endswith("/v1/reauthuri"), calls
assert calls[0][1].get("method") == "POST", calls[0][1]
assert calls[0][1].get("json_body", {}).get("refresh_token") == "refresh-1", calls[0][1]

def rejected(url, **kwargs):
    raise p.UpstreamError(401, "reauth grace window lapsed")

with patch.object(p, "_request", side_effect=rejected):
    result = p.plugin.oauth_url(params, ctx)
assert result["url"].startswith("https://auth.truelayer.com/"), result
assert "response_type=code" in result["url"], result
print("reauth runtime checks passed")
`;
  const output = execFileSync("python3", ["-c", python], {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  expect(output.includes("reauth runtime checks passed"), "Python checks did not complete");
});

const referenceDir = process.env.TRUELAYER2ACTUAL_DIR || path.resolve(root, "..", "truelayer2actual");
if (fs.existsSync(referenceDir)) {
  check("truelayer2actual still has its reauth link implementation", () => {
    const client = read(path.join(referenceDir, "src/clients/truelayer.ts"));
    expect(client.includes("generateReauthLink"), "generateReauthLink() was removed");
    expect(client.includes("/v1/reauthuri"), "reference /v1/reauthuri call was removed");

    const oauth = read(path.join(referenceDir, "src/web/oauth.ts"));
    expect(oauth.includes("startReauth"), "startReauth() was removed");
    expect(oauth.includes("status !== 401 && status !== 400 && status !== 404"),
      "reference full-auth fallback was removed");
  });
} else {
  console.log(`skip - truelayer2actual not found at ${referenceDir} (set TRUELAYER2ACTUAL_DIR to check it)`);
}

if (failures.length) {
  console.error(`\nreauth check failed: ${failures.length} check(s) failed`);
  process.exit(1);
}
console.log("\nreauth link check: OK");
