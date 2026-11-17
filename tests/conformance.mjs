// Sends genuine, tampered, stale and malformed callbacks to a receiver and checks each answer.
// Usage: node tests/conformance.mjs <receiver_url> <secret>
import { createHmac, randomUUID } from "node:crypto";

const [url, secret] = process.argv.slice(2);
const now = () => Math.floor(Date.now() / 1000);
const sign = (s, t, body) => `t=${t},v1=${createHmac("sha256", s).update(`${t}.${body}`).digest("hex")}`;

// Non-ASCII text catches receivers that re-encode the body before verifying it.
const completed = () => JSON.stringify({
  event: "slice.completed", event_id: `evt_${randomUUID()}`, created_at: new Date().toISOString(),
  data: { id: "slc_test", status: "succeeded", metadata: { order: "Bestellung Nr. 42 — Ünïcødé" }, result: { print_time_s: 1855, filament_g: 8.19 }, error: null },
});
const failed = () => JSON.stringify({
  event: "slice.failed", event_id: `evt_${randomUUID()}`, created_at: new Date().toISOString(),
  data: { id: "slc_test2", status: "failed", result: null, error: { code: "model_out_of_bed", message: "The model does not fit on this printer's bed." } },
});

async function send(body, header, method = "POST") {
  const headers = { "content-type": "application/json" };
  if (header !== null) headers["superslice-signature"] = header;
  const res = await fetch(url, { method, headers, body: method === "POST" ? body : undefined });
  return { status: res.status, text: (await res.text()).trim() };
}

const genuine = completed();
const cases = [
  ["genuine callback", () => send(genuine, sign(secret, now(), genuine)), 200, "ok"],
  ["same event again", () => send(genuine, sign(secret, now(), genuine)), 200, "duplicate"],
  ["failed-slice event", () => { const b = failed(); return send(b, sign(secret, now(), b)); }, 200, "ok"],
  ["signed 2 minutes ago", () => { const b = completed(); return send(b, sign(secret, now() - 120, b)); }, 200, "ok"],
  ["one of two v1 values matches (secret rotation)", () => { const b = completed(); return send(b, `${sign("whsec_old", now(), b)},${sign(secret, now(), b).split(",")[1]}`); }, 200, "ok"],
  ["body changed after signing", () => { const b = completed(); return send(b.replace("8.19", "0.19"), sign(secret, now(), b)); }, 400],
  ["signed with another secret", () => { const b = completed(); return send(b, sign("whsec_wrong", now(), b)); }, 400],
  ["signed 10 minutes ago (replay)", () => { const b = completed(); return send(b, sign(secret, now() - 600, b)); }, 400],
  ["signed 10 minutes in the future", () => { const b = completed(); return send(b, sign(secret, now() + 600, b)); }, 400],
  ["no signature header", () => send(completed(), null), 400],
  ["malformed header", () => send(completed(), "garbage"), 400],
  ["timestamp missing", () => { const b = completed(); return send(b, sign(secret, now(), b).split(",")[1]); }, 400],
  ["GET request", () => send("", null, "GET"), 400],
];

let failures = 0;
for (const [name, run, status, text] of cases) {
  const r = await run();
  const ok = r.status === status || (status === 400 && r.status >= 400 && r.status < 500);
  const textOk = text === undefined || r.text === text;
  if (!ok || !textOk) failures++;
  console.log(`${ok && textOk ? "PASS" : "FAIL"} ${name}: ${r.status} ${r.text.slice(0, 40)}`);
}
console.log(failures ? `${failures} FAILED` : "ALL PASSED");
process.exit(failures ? 1 : 0);
