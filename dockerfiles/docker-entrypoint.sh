#!/sbin/tini /bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2021 Olliver Schinagl <oliver@schinagl.nl>
# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#
# A beginning user should be able to docker run image bash (or sh) without
# needing to learn about --entrypoint
# https://github.com/docker-library/official-images#consistency

set -eu

if [ ! -d "/run/clamav" ]; then
	install -d -g "clamav" -m 775 -o "clamav" "/run/clamav"
fi

# Assign ownership to the database directory, just in case it is a mounted volume
chown -R clamav:clamav /var/lib/clamav

# run command if it is not starting with a "-" and is an executable in PATH
if [ "${#}" -gt 0 ] && \
   [ "${1#-}" = "${1}" ] && \
   command -v "${1}" > "/dev/null" 2>&1; then
	# Ensure healthcheck always passes
	CLAMAV_NO_CLAMD="true" exec "${@}"
else
	if [ "${#}" -ge 1 ] && \
	   [ "${1#-}" != "${1}" ]; then
		# If an argument starts with "-" pass it to clamd specifically
		exec clamd "${@}"
	fi
	# else default to running clamav's servers

	# Help tiny-init a little
	mkdir -p "/run/lock"
	ln -f -s "/run/lock" "/var/lock"

	# Ensure we have some virus data, otherwise clamd refuses to start
	if [ ! -f "/var/lib/clamav/main.cvd" ]; then
		echo "Updating initial database"
		freshclam --foreground --stdout
	fi

	if [ "${CLAMAV_NO_CLAMD:-false}" != "true" ]; then
		echo "Starting ClamAV"
		if [ -S "/run/clamav/clamd.sock" ]; then
			unlink "/run/clamav/clamd.sock"
		fi
		clamd --foreground &
		while [ ! -S "/run/clamav/clamd.sock" ]; do
			if [ "${_timeout:=0}" -gt "${CLAMD_STARTUP_TIMEOUT:=1800}" ]; then
				echo
				echo "Failed to start clamd"
				exit 1
			fi
			printf "\r%s" "Socket for clamd not found yet, retrying (${_timeout}/${CLAMD_STARTUP_TIMEOUT}) ..."
			sleep 1
			_timeout="$((_timeout + 1))"
		done
		echo "socket found, clamd started."
	fi

	if [ "${CLAMAV_NO_FRESHCLAMD:-false}" != "true" ]; then
		echo "Starting Freshclamd"
		freshclam \
		          --checks="${FRESHCLAM_CHECKS:-1}" \
		          --daemon \
		          --foreground \
		          --stdout \
		          --user="clamav" \
			  &
	fi

	if [ "${CLAMAV_NO_MILTERD:-true}" != "true" ]; then
		echo "Starting clamav milterd"
		clamav-milter &
	fi

	# Wait forever (or until canceled)
	exec tail -f "/dev/null"
fi

exit 0
