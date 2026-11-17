# Superslice examples

Ready-to-copy code for integrating with the Superslice API.

## Callback receivers

When a slice finishes, Superslice sends the result to your `callback_url` as a `POST`. Anyone on the internet can send a request to that URL, so every callback is signed. Check the signature before you trust the result.

| Language | File | Run |
|---|---|---|
| Node.js 18+ | [node/receiver.mjs](node/receiver.mjs) | `node receiver.mjs` |
| Python 3.10+ | [python/receiver.py](python/receiver.py) | `python3 receiver.py` |
| PHP 7.4+ | [php/receiver.php](php/receiver.php) | `php -S 0.0.0.0:8000 receiver.php`, or put it on your web server |
| Go 1.21+ | [go/main.go](go/main.go) | `go run .` |

Each one uses only the language's standard library. Set `SUPERSLICE_WEBHOOK_SECRET` to the signing secret from your dashboard. `PORT` defaults to 8000.

The verify function in each file is the part to copy into your own app. It takes the secret, the header and the raw body, and works with any web framework.

### How the signature works

```
Superslice-Signature: t=1763028004,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd
```

1. `v1` is the hex HMAC-SHA256 of `{t}.{raw request body}`, keyed with your signing secret.
2. Compute it over the **raw bytes** you received. Parsing the JSON and re-encoding it changes the bytes and breaks the check.
3. Compare with a constant-time function (`timingSafeEqual`, `hmac.compare_digest`, `hash_equals`, `hmac.Equal`).
4. Reject the callback if `t` is more than 5 minutes from your clock. This stops someone replaying an old callback.
5. Accept the callback if any `v1` value matches. While a secret is being rotated, a header can carry two.

### Handling events

- Answer with a 2xx status quickly, within 10 seconds. Do slow work after responding. Anything else counts as a failure, and Superslice retries after 1 minute, 5 minutes, 30 minutes, then hourly for 24 hours.
- The same event can arrive more than once. Use `event_id` to ignore repeats. The examples keep seen IDs in memory, or in a temp file for PHP; use your database in production.
- `event` is `slice.completed` or `slice.failed`. `data` is the same slice object `GET /v1/slices/{id}` returns.

## Testing

`tests/run-all.sh` starts every receiver in Docker and runs [tests/conformance.mjs](tests/conformance.mjs) against it. The test sends genuine callbacks, a repeat, a body changed after signing, a wrong secret, timestamps 10 minutes old and 10 minutes ahead, and missing or malformed headers. To test your own receiver:

```
node tests/conformance.mjs http://localhost:8000/ whsec_your_test_secret
```
