// The browser half of the quickstart.
//
// Every call passes credentials: "include", so the browser attaches the
// httpOnly cookies. This code never sees a token: it reads only the CSRF
// cookie, and echoes it back as a header on every unsafe request.

// Where the API lives. Empty when the page and the API share an origin.
const API = "";

// SET THIS to the name of the CSRF cookie your server sets:
//   "__Host-signet-csrf"    over HTTPS, with the default settings
//   "signet-csrf"           over plain http://, with COOKIE_SECURE=False
//   "__Secure-signet-csrf"  over HTTPS, with COOKIE_DOMAIN set
// It is different again when COOKIE_PREFIX or COOKIE_CSRF_NAME is set.
const CSRF_COOKIE = "__Host-signet-csrf";

const CSRF_HEADER = "X-CSRF-Token";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);

function readCookie(name) {
  const prefix = `${name}=`;
  const found = document.cookie
    .split("; ")
    .find((part) => part.startsWith(prefix));
  return found ? found.slice(prefix.length) : "";
}

// Login needs no CSRF header, but it only accepts a JSON body.
export async function login(username, password) {
  const response = await fetch(`${API}/api/auth/login`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return response.ok;
}

// Resolves true once new cookies are set, false when the session is over.
// Calls made while a refresh is in flight share it rather than start another.
let refreshing = null;

export function refresh() {
  refreshing ??= fetch(`${API}/api/auth/refresh`, {
    method: "POST",
    credentials: "include",
    headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
  })
    .then((response) => response.ok)
    .finally(() => {
      refreshing = null;
    });
  return refreshing;
}

export async function verify() {
  const response = await fetch(`${API}/api/auth/verify`, {
    credentials: "include",
  });
  return response.ok;
}

export async function logout() {
  const response = await fetch(`${API}/api/auth/logout`, {
    method: "POST",
    credentials: "include",
    headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
  });
  return response.ok;
}

// Your own API views: the header on every unsafe method, and one refresh
// and retry when the access token is rejected. The CSRF cookie is read
// again for the retry, because every refresh replaces it.
export async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const send = () => {
    const headers = new Headers(options.headers);
    if (!SAFE_METHODS.has(method)) {
      headers.set(CSRF_HEADER, readCookie(CSRF_COOKIE));
    }
    return fetch(`${API}${path}`, {
      ...options,
      method,
      headers,
      credentials: "include",
    });
  };
  const response = await send();
  if (response.status === 401 && (await refresh())) {
    return send();
  }
  return response;
}
