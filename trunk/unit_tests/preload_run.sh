#!/bin/sh
# Helper script to run a program under electric-fence / duma

# prevent core dumps
ulimit -c 0
LD_PRELOAD=$LIBPRELOAD
export LD_PRELOAD
exec $@
