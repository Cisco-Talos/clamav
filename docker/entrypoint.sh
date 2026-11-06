#!/bin/bash
set -Eeuo pipefail

if [[ "${1:-clamd}" != clamd ]]; then
    exec "$@"
fi
shift || true

database=/var/lib/clamav
mkdir -p "$database" /var/log/clamav
if [[ ! -f /etc/clamav/clamd.conf || ! -f /etc/clamav/freshclam.conf ]]; then
    echo 'Missing clamd.conf or freshclam.conf in /etc/clamav.' >&2
    exit 1
fi

clamd_config=/etc/clamav/clamd.conf
if [[ -n "${CLAMD_MAX_THREADS+x}" ]]; then
    if [[ ! "$CLAMD_MAX_THREADS" =~ ^[1-9][0-9]{0,9}$ ]] ||
       ((CLAMD_MAX_THREADS > 2147483647)); then
        echo 'CLAMD_MAX_THREADS must be an integer from 1 to 2147483647.' >&2
        exit 1
    fi
    # Preserve the authoritative config, including a read-only bind mount.
    # Replace all active occurrences; appending alone can leave the first active.
    install -d -m 755 /run/clamav
    clamd_config=/run/clamav/clamd.conf
    sed '/^[[:space:]]*MaxThreads[[:space:]]/d' /etc/clamav/clamd.conf > "$clamd_config"
    printf '\nMaxThreads %s\n' "$CLAMD_MAX_THREADS" >> "$clamd_config"
    chmod 644 "$clamd_config"
fi

if [[ "${CLAMAV_NO_FRESHCLAMD:-false}" != true ]]; then
    if ! gosu clamav test -w "$database"; then
        echo '/var/lib/clamav must be writable by clamav (UID 100) for FreshClam.' >&2
        exit 1
    fi
    if [[ ! -f "$database/main.cvd" && ! -f "$database/main.cld" ]] ||
       [[ ! -f "$database/daily.cvd" && ! -f "$database/daily.cld" ]]; then
        freshclam --config-file=/etc/clamav/freshclam.conf
    fi
fi

children=()
shutdown() {
    trap - TERM INT
    if ((${#children[@]})); then
        kill -TERM "${children[@]}" 2>/dev/null || true
        wait "${children[@]}" 2>/dev/null || true
    fi
}
trap 'shutdown; exit 0' TERM INT

clamd --config-file="$clamd_config" --foreground=true "$@" &
children+=("$!")
if [[ "${CLAMAV_NO_FRESHCLAMD:-false}" != true ]]; then
    freshclam --config-file=/etc/clamav/freshclam.conf --daemon --foreground=true &
    children+=("$!")
fi

set +e
wait -n "${children[@]}"
status=$?
set -e
shutdown
# A daemon exiting on its own, even with status 0, must not leave a healthy
# container that silently stopped scanning or updating signatures.
if ((status == 0)); then status=1; fi
exit "$status"
