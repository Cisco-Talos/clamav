#!/bin/sh
# Helper script to run a program under electric-fence / duma

# prevent core dumps
ulimit -c 0 || true
LD_PRELOAD=$LIBPRELOAD
export LD_PRELOAD
export CK_DEFAULT_TIMEOUT=40
exec $@
