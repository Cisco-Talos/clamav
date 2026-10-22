#!/bin/bash
set -Eeuo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_root=$(cd -- "$here/.." && pwd)
image=${IMAGE:-antivirus:latest}
database=$(realpath -- "${1:-$source_root/db}")
container="clamav-optimized-test-$$"
inputs=$(mktemp -d "$here/.test-XXXXXXXX")
chmod 755 "$inputs"
cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf -- "$inputs"
}
trap cleanup EXIT
printf 'An ordinary clean text document.\n' > "$inputs/clean.txt"
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$inputs/eicar.com"
chmod 644 "$inputs"/*

docker run --rm --entrypoint clamscan "$image" --version
docker run --rm --entrypoint freshclam "$image" --version
docker run -d --name "$container" --network none \
    --env CLAMAV_NO_FRESHCLAMD=true \
    --env CLAMD_MAX_THREADS=4 \
    --mount "type=bind,source=$database,target=/var/lib/clamav,readonly" \
    --mount "type=bind,source=$inputs,target=/scan,readonly" \
    "$image" >/dev/null

ready=false
for ((i=0; i<120; i++)); do
    if docker exec "$container" /usr/local/bin/healthcheck.sh 2>/dev/null; then
        ready=true
        break
    fi
    if [[ "$(docker inspect --format '{{.State.Running}}' "$container")" != true ]]; then
        docker logs "$container"
        exit 1
    fi
    sleep 2
done
if [[ "$ready" != true ]]; then
    docker logs "$container"
    echo 'Timed out waiting for clamd TCP PING.' >&2
    exit 1
fi
docker exec "$container" test ! -S /tmp/clamd.sock
docker exec "$container" grep -qx 'MaxThreads 4' /run/clamav/clamd.conf
stats=$(printf 'nSTATS\n' | docker exec -i "$container" nc -w 10 127.0.0.1 3310)
if [[ ! "$stats" =~ THREADS:.*max\ 4\  ]]; then
    echo 'Daemon STATS did not report the configured four-worker limit.' >&2
    exit 1
fi
# Exercise the deployment's actual protocol: TCP command plus a shared path.
clean_reply=$(printf 'nSCAN /scan/clean.txt\n' | docker exec -i "$container" nc -w 10 127.0.0.1 3310)
eicar_reply=$(printf 'nSCAN /scan/eicar.com\n' | docker exec -i "$container" nc -w 10 127.0.0.1 3310)
if [[ "$clean_reply" != '/scan/clean.txt: OK' || "$eicar_reply" != *FOUND ]]; then
    printf 'Unexpected TCP SCAN results: %s | %s\n' "$clean_reply" "$eicar_reply" >&2
    exit 1
fi
docker exec "$container" clamdscan --no-summary /scan/clean.txt
set +e
result=$(docker exec "$container" clamdscan --no-summary /scan/eicar.com 2>&1)
status=$?
set -e
printf '%s\n' "$result"
if [[ "$status" != 1 || "$result" != *FOUND* ]]; then
    echo 'Expected clamd TCP scan to detect EICAR with exit code 1.' >&2
    exit 1
fi
docker stop --time 30 "$container" >/dev/null
exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$container")
if [[ "$exit_code" != 0 ]]; then
    echo "Container did not stop cleanly: $exit_code" >&2
    exit 1
fi
echo 'PASS: versions, worker override, TCP PING, TCP path scans, clean scan, EICAR detection, no Unix socket, graceful shutdown.'
