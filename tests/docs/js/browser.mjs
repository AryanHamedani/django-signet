// A browser page at BASE, as far as client.js can tell: document.cookie
// shows the non-httpOnly cookies, and fetch() keeps a path-scoped cookie
// jar. Secure and Domain are ignored, as a browser does for localhost.
// Adapted from the Task 3 reviewer's probe harness.

const realFetch = globalThis.fetch;
export const jar = new Map(); // name -> { value, path, httpOnly }
export const requests = []; // "METHOD /path STATUS"
// A path that answers 401 whatever the session: a retry that loops on it
// never ends, so the test sees the loop as a timeout.
export const ALWAYS_401 = "/always-401";

function parseSetCookie(header) {
  const [pair, ...attributes] = header.split(";").map((s) => s.trim());
  const cookie = {
    name: pair.slice(0, pair.indexOf("=")),
    value: pair.slice(pair.indexOf("=") + 1),
    path: "/",
    httpOnly: false,
    expired: false,
  };
  for (const attribute of attributes) {
    const [key, value] = attribute.split("=");
    const lower = key.toLowerCase();
    if (lower === "path") cookie.path = value;
    if (lower === "httponly") cookie.httpOnly = true;
    if (lower === "max-age" && Number(value) <= 0) cookie.expired = true;
  }
  return cookie;
}

function pathMatches(cookiePath, path) {
  return (
    path === cookiePath ||
    (path.startsWith(cookiePath) &&
      (cookiePath.endsWith("/") || path[cookiePath.length] === "/"))
  );
}

export function installBrowser(base) {
  globalThis.document = {
    get cookie() {
      return [...jar.entries()]
        .filter(([, c]) => !c.httpOnly)
        .map(([name, c]) => `${name}=${c.value}`)
        .join("; ");
    },
  };
  globalThis.fetch = async (url, init = {}) => {
    if (init.credentials !== "include") {
      throw new Error(`fetch without credentials: "include": ${url}`);
    }
    const target = new URL(url, base);
    if (target.pathname === ALWAYS_401) {
      requests.push(`${init.method || "GET"} ${target.pathname} 401`);
      return new Response(null, { status: 401 });
    }
    const headers = new Headers(init.headers);
    const cookie = [...jar.entries()]
      .filter(([, c]) => pathMatches(c.path, target.pathname))
      .map(([name, c]) => `${name}=${c.value}`)
      .join("; ");
    if (cookie) headers.set("Cookie", cookie);
    const response = await realFetch(target, { ...init, headers });
    for (const header of response.headers.getSetCookie()) {
      const parsed = parseSetCookie(header);
      if (parsed.expired) jar.delete(parsed.name);
      else jar.set(parsed.name, parsed);
    }
    requests.push(`${init.method || "GET"} ${target.pathname} ${response.status}`);
    return response;
  };
}
