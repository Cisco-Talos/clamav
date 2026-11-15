# RAR scanner fixtures

These archives exercise the reader-only `rars` integration across RAR 1.x,
RAR 2.x, RAR 3/4, RAR 5, and RAR 7 structures. They include solid archives,
SFX, comments, encryption, standard filters, redirections, service records,
split members, malformed inputs, and a non-standard RAR3 VM program.

Except for `rar3-sfx.exe`, the fixtures were copied from the `rars` reader
corpus at commit `e01b925aaf49a40995e1cae23819cb60383121c3`.
`rar3-sfx.exe` combines an existing ClamAV PE test stub with the synthetic
`rar3-solid.rar` fixture. See `FIXTURE-LICENSES.md` for provenance and license
terms.

The tests intentionally store only the first volume of `rar5-split-part1.rar`.
This verifies that ClamAV does not discover sibling volumes by pathname.

`rar5-oversized-then-small.rar.b64` is a base64-encoded synthetic RAR5
archive generated with the pinned `rars` writer. Its first independent member
expands beyond a 1 KiB file limit, while its later member remains scannable.
