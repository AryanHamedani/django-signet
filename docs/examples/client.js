// The browser half of the quickstart.
//
// Every call passes credentials: "include", so the browser attaches the
// httpOnly cookies. This code never sees a token: it reads only the CSRF
// cookie, and echoes it back as a header on every unsafe request.

// Where the API lives. Empty when the page and the API share an origin.
const API = "";

// The server's default CSRF cookie. It is "signet-csrf" under
// COOKIE_SECURE=False, and "__Secure-signet-csrf" once COOKIE_DOMAIN is set.
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

// 200: new cookies are set. 401: the session is over; log in again.
// 403: the CSRF header was missing or wrong, and the cookies are untouched.
export async function refresh() {
  const response = await fetch(`${API}/api/auth/refresh`, {
    method: "POST",
    credentials: "include",
    headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
  });
  return response.ok;
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
