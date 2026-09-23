const c = await import("/static/client.js");
await c.login("alice", "your-password"); // => true
await c.verify(); // => true
(await c.api("/api/notes")).status; // => 200
(await c.api("/api/notes", { method: "POST" })).status; // => 201
await c.refresh(); // => true
await c.logout(); // => true
await c.verify(); // => false
