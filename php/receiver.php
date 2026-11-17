<?php
// Superslice callback receiver for PHP 7.4+. No dependencies.
// Run locally: SUPERSLICE_WEBHOOK_SECRET=whsec_... php -S 0.0.0.0:8000 receiver.php
// On a normal web server, point your callback URL at this file.

const TOLERANCE_S = 300;

/**
 * True when $header (the Superslice-Signature value) signs $rawBody with $secret
 * and its timestamp is within 5 minutes of $now. Verify the raw bytes, before parsing JSON.
 */
function superslice_verify(string $secret, ?string $header, string $rawBody, ?int $now = null): bool
{
    $now = $now ?? time();
    $t = null;
    $signatures = [];
    foreach (explode(',', $header ?? '') as $part) {
        $pair = explode('=', trim($part), 2);
        if (count($pair) !== 2) continue;
        if ($pair[0] === 't' && ctype_digit($pair[1])) $t = (int) $pair[1];
        if ($pair[0] === 'v1' && $pair[1] !== '') $signatures[] = $pair[1];
    }
    if ($t === null || !$signatures || abs($now - $t) > TOLERANCE_S) return false;
    $expected = hash_hmac('sha256', $t . '.' . $rawBody, $secret);
    foreach ($signatures as $signature) {
        if (hash_equals($expected, $signature)) return true;
    }
    return false;
}

function superslice_handle(array $event): void
{
    $log = fopen('php://stderr', 'w');
    if ($event['event'] === 'slice.completed') {
        $r = $event['data']['result'];
        fwrite($log, "slice {$event['data']['id']}: {$r['print_time_s']} s, {$r['filament_g']} g\n");
    } elseif ($event['event'] === 'slice.failed') {
        fwrite($log, "slice {$event['data']['id']} failed: {$event['data']['error']['code']}\n");
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') !== __FILE__) return;

$secret = getenv('SUPERSLICE_WEBHOOK_SECRET') ?: '';
$rawBody = file_get_contents('php://input');
if ($secret === '' || $_SERVER['REQUEST_METHOD'] !== 'POST'
    || !superslice_verify($secret, $_SERVER['HTTP_SUPERSLICE_SIGNATURE'] ?? null, $rawBody)) {
    http_response_code(400);
    echo 'invalid signature';
    return;
}
$event = json_decode($rawBody, true);

// Superslice may deliver an event more than once. Use your database in production;
// this demo keeps seen event IDs in a temp file because each PHP request starts fresh.
$seenFile = sys_get_temp_dir() . '/superslice-seen-events';
$seen = is_file($seenFile) ? file($seenFile, FILE_IGNORE_NEW_LINES) : [];
if (in_array($event['event_id'], $seen, true)) {
    echo 'duplicate';
    return;
}
file_put_contents($seenFile, $event['event_id'] . "\n", FILE_APPEND | LOCK_EX);
echo 'ok';
superslice_handle($event);
