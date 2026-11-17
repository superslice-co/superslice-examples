// Superslice callback receiver for Node.js 18+. No dependencies.
// Run: SUPERSLICE_WEBHOOK_SECRET=whsec_... node receiver.mjs
import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";

const SECRET = process.env.SUPERSLICE_WEBHOOK_SECRET;
const PORT = Number(process.env.PORT ?? 8000);
const TOLERANCE_S = 300;

/**
 * True when `header` (the Superslice-Signature value) signs `rawBody` with `secret`
 * and its timestamp is within 5 minutes of `now`. Verify the raw bytes, before parsing JSON.
 */
export function verify(secret, header, rawBody, now = Math.floor(Date.now() / 1000)) {
  let t = null;
  const signatures = [];
  for (const part of (header ?? "").split(",")) {
    const [key, value] = part.trim().split("=", 2);
    if (key === "t" && /^\d+$/.test(value ?? "")) t = Number(value);
    if (key === "v1" && value) signatures.push(value);
  }
  if (t === null || signatures.length === 0 || Math.abs(now - t) > TOLERANCE_S) return false;
  const expected = Buffer.from(createHmac("sha256", secret).update(`${t}.`).update(rawBody).digest("hex"));
  return signatures.some((s) => {
    const given = Buffer.from(s);
    return given.length === expected.length && timingSafeEqual(given, expected);
  });
}

// Superslice may deliver an event more than once. Store event_id in your database in production.
const seen = new Set();

function handle(event) {
  if (event.event === "slice.completed") {
    const { id, result } = event.data;
    console.log(`slice ${id}: ${result.print_time_s} s, ${result.filament_g} g`);
  } else if (event.event === "slice.failed") {
    console.log(`slice ${event.data.id} failed: ${event.data.error.code}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (!SECRET) throw new Error("set SUPERSLICE_WEBHOOK_SECRET");
  createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const rawBody = Buffer.concat(chunks);
      if (req.method !== "POST" || !verify(SECRET, req.headers["superslice-signature"], rawBody)) {
        res.writeHead(400).end("invalid signature");
        return;
      }
      const event = JSON.parse(rawBody.toString("utf8"));
      if (seen.has(event.event_id)) {
        res.writeHead(200).end("duplicate");
        return;
      }
      seen.add(event.event_id);
      // Answer quickly; do slow work (emails, orders) after responding or in a queue.
      res.writeHead(200).end("ok");
      handle(event);
    });
  }).listen(PORT, () => console.log(`listening on ${PORT}`));
}
