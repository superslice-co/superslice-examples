#!/usr/bin/env bash
# Starts every receiver in Docker and runs the conformance test against each one.
# Usage: tests/run-all.sh
set -euo pipefail
cd "$(dirname "$0")/.."
SECRET="whsec_conformance_$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
NET="superslice-examples-test"
docker network create "$NET" >/dev/null 2>&1 || true

declare -A IMAGE=(
  [node]="node:24-bookworm-slim"
  [python]="python:3.13-slim"
  [php]="php:8.4-cli"
  [go]="golang:1.25-bookworm"
)
declare -A CMD=(
  [node]="node receiver.mjs"
  [python]="python3 receiver.py"
  [php]="php -S 0.0.0.0:8000 receiver.php"
  [go]="go run ."
)

failed=0
for lang in node python php go; do
  name="rx-$lang"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --network "$NET" -e SUPERSLICE_WEBHOOK_SECRET="$SECRET" \
    -v "$PWD/$lang:/app:ro" -w /app "${IMAGE[$lang]}" ${CMD[$lang]} >/dev/null
  for _ in $(seq 1 120); do
    docker logs "$name" 2>&1 | grep -qiE "listening|started" && break
    sleep 1
  done
  echo "== $lang"
  docker run --rm --network "$NET" -v "$PWD/tests:/tests:ro" node:24-bookworm-slim \
    node /tests/conformance.mjs "http://$name:8000/" "$SECRET" || failed=1
  docker rm -f "$name" >/dev/null
done
docker network rm "$NET" >/dev/null
exit $failed
