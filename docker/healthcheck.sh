#!/bin/sh
set -eu
reply=$(printf 'nPING\n' | nc -w 3 127.0.0.1 3310)
[ "$reply" = PONG ]
