# Keeping the customization current

`upstream` points to `https://github.com/Cisco-Talos/clamav.git`. The local `main`
branch remains the original upstream checkout and tracks `upstream/main`.
The repository remains shallow; a full-history clone is not required.

- `perf/scan-throughput-memory`: scanner optimizations, regression tests and
  reproducible benchmark tools for upstream review.
- `custom/optimized-antivirus`: the review branch plus the local Debian image,
  normative `AGENTS.md`, maintenance helpers and historical experiment reports.

## Update from ClamAV

Start on `custom/optimized-antivirus`, with committed work:

```sh
./maintenance/update-upstream.sh
```

The helper fetches upstream main without tags, merges it into the review branch,
then merges that branch into the deployment branch. It retains existing commits
and does not require force-pushes. If the shallow boundary prevents Git from
finding a common ancestor, it deepens in bounded increments (100, 500, 1,000).
It never silently downloads the complete history or merges unrelated histories.

If a merge conflicts, resolve and commit it on the branch where the script
stopped. If that is the review branch, then finish with:

```sh
git switch custom/optimized-antivirus
git merge --no-edit perf/scan-throughput-memory
```

Rebuild and run the checks in `AGENTS.md` before deploying. In particular, review
changes to C structure layouts and regenerate the corresponding Rust bindings;
recheck image-resize equivalence when updating the `image` dependency. Re-run
benchmarks against the new upstream base, since old percentages do not establish
the benefit against a different release.

To refresh the separate pristine local branch, when needed:

```sh
git switch main
git merge --ff-only upstream/main
git switch custom/optimized-antivirus
```

New performance fixes should go on the review branch first, then be merged into
the deployment branch. Docker or private deployment changes belong only on the
latter. If upstream accepts some or all of the patches, inspect what remains in
`git diff upstream/main...perf/scan-throughput-memory`; retire accepted patches
and refresh the PR description instead of reintroducing superseded code.

The helper was exercised in temporary repositories with a depth-1 clone, an
upstream advance, dirty work, and a deliberate merge conflict. Normal updating
preserved both custom branches and shallow history; dirty work was refused;
conflicts retained the index for resolution and left deployment unchanged.

## Publish the prepared review later

GitHub authentication and the user's fork are intentionally deferred. Nothing
has been pushed and no upstream PR has been opened. Once ready:

```sh
gh auth login --hostname github.com --web --git-protocol https
gh repo fork Cisco-Talos/clamav --clone=false --remote --remote-name origin
git remote -v
git push --set-upstream origin perf/scan-throughput-memory
```

Confirm that `origin` is your fork and `upstream` is Cisco-Talos. Then, from the
custom branch where the prepared body is available:

```sh
gh pr create --draft --repo Cisco-Talos/clamav --base main \
  --head YOUR_GITHUB_USERNAME:perf/scan-throughput-memory \
  --title 'Reduce logical-signature scan overhead and reuse matching work' \
  --body-file maintenance/PR.md
```

Replace `YOUR_GITHUB_USERNAME`. The custom deployment branch does not need to be
published for the PR. If you want a backup of it, push it separately to your fork.
`db/`, Docker configuration, build products and raw benchmark outputs must remain
untracked. The local Docker image embeds private download URLs; it is separate
from the public source review.

This checkout also ignores `db/`, `docker/config/`, and temporary Docker test
inputs in `.git/info/exclude`, so they remain ignored when switching to the
review branch, where the deployment-specific ignore file is absent. Preserve
equivalent local exclusions when setting up another checkout with private data.
