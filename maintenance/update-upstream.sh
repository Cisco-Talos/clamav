#!/bin/bash
# Merge upstream into the review branch, then into the deployment branch.
# Existing commits are retained; no rebase or force-push is required.
set -Eeuo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd -- "$here/.."
review=perf/scan-throughput-memory
deployment=custom/optimized-antivirus
starting_branch=$(git symbolic-ref --quiet --short HEAD)
if [[ "$starting_branch" != "$review" && "$starting_branch" != "$deployment" ]]; then
    echo "Start on $review or $deployment." >&2
    exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
    echo 'Commit or stash your work before updating; the working tree must be clean.' >&2
    exit 1
fi
git show-ref --verify --quiet "refs/heads/$review"
git remote get-url upstream >/dev/null
git fetch --no-tags upstream main

# A depth-1 clone normally already contains the old common ancestor. Deepen
# only when Git cannot find one; do not download the complete history by default.
for deepen in 0 100 500 1000; do
    if git merge-base "$review" upstream/main >/dev/null; then break; fi
    if ((deepen == 0)); then continue; fi
    git fetch --no-tags --deepen="$deepen" upstream main
done
if ! git merge-base "$review" upstream/main >/dev/null; then
    echo 'No common ancestor found after bounded deepening. Stop and inspect the histories.' >&2
    echo 'For a verified common upstream, git fetch --unshallow --no-tags upstream is available.' >&2
    exit 1
fi
git switch "$review"
if ! git merge --no-edit upstream/main; then
    echo "Resolve and commit the upstream merge on $review; deployment has not been updated." >&2
    exit 1
fi
if [[ "$starting_branch" == "$deployment" ]]; then
    git switch "$deployment"
    if ! git merge --no-edit "$review"; then
        echo "Resolve and commit the deployment merge on $deployment." >&2
        exit 1
    fi
fi
echo 'Upstream merged. Rebuild and run the checks in AGENTS.md before publishing or deploying.'
