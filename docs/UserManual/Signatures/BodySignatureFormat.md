# Body-based Signature Content Format

ClamAV stores all body-based signatures in a hexadecimal format. In this section by a hex-signature we mean a fragment of malware’s body converted into a hexadecimal string which can be additionally extended using various wildcards.

## Hexadecimal format

You can use `sigtool --hex-dump` to convert any data into a hex-string:

```bash
zolw@localhost:/tmp/test$ sigtool --hex-dump
How do I look in hex?
486f7720646f2049206c6f6f6b20696e206865783f0a
```

## Wildcards

ClamAV supports the following wildcards for hex-signatures:

- `??`

  Match any byte.

- `a?`

  Match a high nibble (the four high bits).

- `?a`

  Match a low nibble (the four low bits).

- `*`

  Match any number of bytes.

- `{n}`

  Match `n` bytes.

- `{-n}`

  Match `n` or less bytes.

- `{n-}`

  Match `n` or more bytes.

- `{n-m}`

  Match between `n` and `m` bytes (where `m > n`).

- `HEXSIG[x-y]aa` or `aa[x-y]HEXSIG`

  Match `aa` anchored to a hex-signature, see [Bugzilla ticket 776](https://bugzilla.clamav.net/show_bug.cgi?id=776) for discussion and
  examples.

The range signatures `*` and `{}` virtually separate a hex-signature into two parts, eg. `aabbcc*bbaacc` is treated as two sub-signatures `aabbcc` and `bbaacc` with any number of bytes between them. It’s a requirement that each sub-signature includes a block of two static characters somewhere in its body. Note that there is one exception to this restriction; that is when the range wildcard is of the form `{n}` with `n<128`. In this case, ClamAV uses an optimization and translates `{n}` to the string consisting of `n ??` character wildcards. Character wildcards do not divide hex signatures into two parts and so the two static character requirement does not apply.

## Character classes

ClamAV supports the following character classes for hex-signatures:

- `(B)`

  Match word boundary (including file boundaries).

- `(L)`

  Match CR, CRLF or file boundaries.

- `(W)`

  Match a non-alphanumeric character.

## Alternate strings

- Single-byte alternates (clamav-0.96) `(aa|bb|cc|...)` or `!(aa|bb|cc|...)` Match a member from a set of bytes (eg: `aa`, `bb`, `cc`, ...).
  - Negation operation can be applied to match any non-member, assumed to be one-byte in length.
  - Signature modifiers and wildcards cannot be applied.

- Multi-byte fixed length alternates `(aaaa|bbbb|cccc|...)` or `!(aaaa|bbbb|cccc|...)` Match a member from a set of multi-byte alternates (eg: aaaa, bbbb, cccc, ...) of n-length.
  - All set members must be the same length.
  - Negation operation can be applied to match any non-member, assumed to be n-bytes in length (clamav-0.98.2).
  - Signature modifiers and wildcards cannot be applied.

- Generic alternates (clamav-0.99) `(alt1|alt2|alt3|...)` Match a member from a set of alternates (eg: alt1, alt2, alt3, ...) that can be of variable lengths.
  - Negation operation cannot be applied.
  - Signature modifiers and nibble wildcards (eg: `??, a?, ?a`) can be applied.
  - Ranged wildcards (eg: `{n-m}`) are limited to a fixed range of less than 128 bytes (eg: `{1} -> {127}`).

Note that using signature modifiers and wildcards classifies the alternate type to be a generic alternate. Thus single-byte alternates and multi-byte fixed length alternates can use signature modifiers and wildcards but will be classified as generic alternate. This means that negation cannot be applied in this situation and there is a slight performance impact.
