#!/bin/sh
# deletes all auto-generated / compiled files

for dir in . doc examples mspack test; do
    while read path; do
        chmod -R a+rwx $dir/$path 2>/dev/null
        rm -vrf $dir/$path
    done < $dir/.gitignore
done
