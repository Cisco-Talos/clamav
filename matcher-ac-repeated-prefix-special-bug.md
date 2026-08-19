# Matcher AC repeated-prefix special-metadata bug

## Status

Fixed on this branch.

Relevant code:

- `libclamav/matcher-ac.c:397`
- `libclamav/matcher-ac.c:1371`
- `libclamav/matcher-ac.c:1463`
- `libclamav/matcher-ac.c:3333`
- `libclamav/matcher-ac.c:3346`
- `unit_tests/check_matchers.c:401`

## Bug summary

The repeated-prefix optimization path in `cli_ac_addsig()` shifted the AC trie
window right for signatures with repeated leading bytes, but it only set:

- `prefix_length[0] = repeated_ppos`
- `prefix_length[1] = repeated_ppos`
- `prefix_length[2] = repeated_ppos`

and did not recompute `special_pattern`.

That was only valid when every skipped prefix token was a single literal byte.
It was wrong when the skipped prefix contained one or more `CLI_MATCH_SPECIAL`
tokens, because special tokens expand to their own min/max byte lengths and
must also advance the prefix-side special counter.

The wildcard / zero-prefix shift path already did this accounting correctly.
The repeated-prefix path had diverged from that logic.

## Why it matters

Backward prefix validation depends on two pieces of metadata being correct:

- `prefix_length[1]` and `prefix_length[2]`
- `special_pattern`

The control flow is:

1. `ac_findmatch()` validates that `pattern->prefix_length[1] <= offset`.
2. `ac_forward_match_branch()` finishes the forward check.
3. It then enters `ac_backward_match_branch()` with
   `specialcnt = pattern->special_pattern - 1`.
4. If a skipped prefix token is `CLI_MATCH_SPECIAL`, `AC_MATCH_CHAR(...)`
   dispatches into `ac_findmatch_special()`, which indexes
   `pattern->special_table[specialcnt]`.

If `special_pattern` was never recomputed after the repeated-prefix shift:

- it could remain `0` even though the skipped prefix contains a special
- `pattern->special_pattern - 1` underflows as an unsigned `uint16_t`
- prefix-side special matching can use the wrong `special_table` entry or read
  out of bounds

If `prefix_length[1]` / `prefix_length[2]` were treated as raw token counts:

- the matcher undercounted the byte span of the skipped prefix
- offset validation and length bookkeeping no longer matched the actual shifted
  prefix

Net effect:

- incorrect matches are possible
- out-of-bounds access is possible in the prefix-side special handling path

## Concrete trigger shape

The problematic signature shape is:

- repeated leading literal bytes, enough to enable
  `select_repeated_prefix_exact_window()`
- at least one `CLI_MATCH_SPECIAL` token in the skipped prefix
- a later static window selected as the AC trie start

Example used in the regression test:

- `ac_mindepth = 4`
- `ac_maxdepth = 4`
- signature hex: `41414141(4243)44454647`
- readable form: `AAAA(BC)DEFG`

How this lays out:

- skipped prefix tokens: `A A A A (BC)`
- shifted AC window: `D E F G`

Correct metadata for that prefix is:

- `prefix_length[0] = 5` token slots
- `prefix_length[1] = 6` minimum bytes
- `prefix_length[2] = 6` maximum bytes
- `special_pattern = 1`

Pre-fix, the repeated-prefix path recorded:

- `prefix_length[0] = 5`
- `prefix_length[1] = 5`
- `prefix_length[2] = 5`
- `special_pattern = 0`

That is the exact mismatch that causes the bug.

## Root cause in code

Before the fix, the repeated-prefix branch in `cli_ac_addsig()` effectively did:

```c
new->prefix = new->pattern;
new->prefix_length[0] = repeated_ppos;
new->prefix_length[1] = repeated_ppos;
new->prefix_length[2] = repeated_ppos;
new->pattern = &new->prefix[repeated_ppos];
new->length[0] -= repeated_ppos;
new->length[1] -= repeated_ppos;
new->length[2] -= repeated_ppos;
```

This assumed that every skipped prefix token consumes exactly one byte and that
no skipped prefix token is special.

That assumption is invalid for signatures containing `CLI_MATCH_SPECIAL`
entries in the skipped prefix.

## Implemented fix

A helper was added at `libclamav/matcher-ac.c:397`:

- `recalculate_prefix_metadata(struct cli_ac_patt *pattern)`

It recomputes all prefix-derived metadata from the actual skipped prefix
tokens:

- resets and recounts `special_pattern`
- recomputes `prefix_length[1]`
- recomputes `prefix_length[2]`
- advances through `special_table[]` in prefix order

The helper is now used in both shift paths:

- wildcard / zero-prefix shift path at `libclamav/matcher-ac.c:3333`
- repeated-prefix shift path at `libclamav/matcher-ac.c:3346`

The repeated-prefix branch now subtracts the recomputed prefix byte lengths:

- `new->length[1] -= new->prefix_length[1]`
- `new->length[2] -= new->prefix_length[2]`

instead of subtracting raw `repeated_ppos`.

## Regression coverage

Added test:

- `test_ac_repeated_prefix_special_metadata`
- `unit_tests/check_matchers.c:401`

What it checks:

1. Initializes a matcher with `ac_mindepth = 4`, `ac_maxdepth = 4`
2. Adds `41414141(4243)44454647`
3. Verifies the shifted pattern metadata directly:
   - prefix token count is `5`
   - prefix min/max byte length is `6`
   - `special_pattern` is `1`
   - shifted suffix length is `4`
4. Builds the trie and confirms that scanning `AAAABCDEFG` detects the
   signature

The test is registered in the matcher suite at
`unit_tests/check_matchers.c:643`.

## Verification performed

Build:

- `make check_clamav`

Test:

- `./unit_tests/check_clamav`

Observed result after adding the regression test:

- total checks increased from `1235` to `1236`
- the new matcher regression passed
- the only remaining failures were pre-existing and unrelated:
  - `test_cl_load`: `Can't verify database integrity`
  - `test_cl_cvdverify`: `CVD_CERTS_DIR not set`

## Suggested follow-up analysis for another agent

1. Check whether any other prefix-shift or trie-window-selection paths assign
   `prefix_length[]` or `special_pattern` manually instead of deriving them
   from the actual skipped prefix tokens.
2. Consider whether `ac_forward_match_branch()` should defensively guard the
   `pattern->special_pattern - 1` handoff for prefix-side matching, even if the
   metadata is expected to be correct.
3. Consider adding an end-to-end test that uses a more complex special token
   shape in the skipped prefix, not only a fixed-length alternate.
4. Review whether there are any similar assumptions elsewhere that equate token
   count with byte length in the presence of `CLI_MATCH_SPECIAL`.
