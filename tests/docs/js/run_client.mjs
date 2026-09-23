// Drive client.js against a live server and print what happened as JSON.
//
//   node run_client.mjs BASE_URL CLIENT_MODULE TRY_IT_FILE
//
// First the tutorial's console session (try_it.js), line by line, then the
// properties that session cannot show: one shared refresh, a retry after
// the access cookie expires, a single retry for a 401 that persists, and
// no retry at all once the session is gone. Requests to the server stay
// sequential: the test database is an in-memory SQLite connection that the
// live server's threads share, and it breaks under concurrent requests.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { ALWAYS_401, installBrowser, jar, requests } from "./browser.mjs";

const [base, clientModule, tryItFile] = process.argv.slice(2);
installBrowser(base);
const c = await import(pathToFileURL(clientModule).href);
const AsyncFunction = (async () => {}).constructor;
const result = { tryIt: [] };

for (const line of readFileSync(tryItFile, "utf8").split("\n")) {
  const match = line.match(/^(.*);\s*\/\/ => (.*)$/);
  if (!match) continue; // the import line: `c` is already the module
  const run = new AsyncFunction("c", `return (${match[1]});`);
  result.tryIt.push({
    line: match[1],
    expected: JSON.parse(match[2]),
    actual: await run(c),
  });
}

const count = (entry) => requests.filter((r) => r.startsWith(entry)).length;
const forgetAccessCookie = () => {
  for (const name of jar.keys()) if (name.includes("access")) jar.delete(name);
};

await c.login("alice", "your-password");
const before = count("POST /api/auth/refresh");
result.concurrentRefresh = await Promise.all([c.refresh(), c.refresh(), c.refresh()]);
result.refreshRequests = count("POST /api/auth/refresh") - before;

forgetAccessCookie();
result.postAfterExpiry = (await c.api("/api/notes", { method: "POST" })).status;

let sent = requests.length;
result.persistent401 = (await c.api(ALWAYS_401, { method: "POST" })).status;
result.requestsForPersistent401 = requests.slice(sent);

jar.clear();
sent = requests.length;
result.postWithoutSession = (await c.api("/api/notes", { method: "POST" })).status;
result.requestsWithoutSession = requests.slice(sent);

result.requests = requests;
console.log(JSON.stringify(result));
