# Logical signatures

Logical signatures allow combining of multiple signatures in extended format using logical operators. They can provide both more detailed and flexible pattern matching. The logical sigs are stored inside `*.ldb` files in the following format:

```
SignatureName;TargetDescriptionBlock;LogicalExpression;Subsig0;
Subsig1;Subsig2;...
```

where:

- `TargetDescriptionBlock` provides information about the engine and target file with comma separated `Arg:Val` pairs. For args where `Val` is a range, the minimum and maximum values should be expressed as `min-max`.

- `LogicalExpression` specifies the logical expression describing the relationship between `Subsig0...SubsigN`. **Basis clause:** 0,1,...,N decimal indexes are SUB-EXPRESSIONS representing `Subsig0, Subsig1,...,SubsigN` respectively. **Inductive clause:** if `A` and `B` are SUB-EXPRESSIONS and `X, Y` are decimal numbers then `(A&B)`, `(A|B)`, `A=X`, `A=X,Y`, `A>X`, `A>X,Y`, `A<X` and `A<X,Y` are SUB-EXPRESSIONS

- `SubsigN` is n-th subsignature in extended format possibly preceded with an offset. There can be specified up to 64 subsigs.

Keywords used in `TargetDescriptionBlock`:

- `Target:X`: A number specifying the type of the target file: [Target Types](FileTypes.md#Target-Types).

- `Engine:X-Y`: Required engine functionality level (range; 0.96). Note that if the `Engine` keyword is used, it must be the first one in the `TargetDescriptionBlock` for backwards compatibility. See the [FLEVEL reference](FunctionalityLevels.md) for details.

- `FileSize:X-Y`: Required file size (range in bytes; 0.96)

- `EntryPoint`: Entry point offset (range in bytes; 0.96)

- `NumberOfSections`: Required number of sections in executable (range; 0.96)

- `Container:CL_TYPE_*`: File type of the container which stores the scanned file.

  Specifying `CL_TYPE_ANY` matches on root objects only (i.e. the target file is explicitely _not_ in a container). Chances slim that you would want to use `CL_TYPE_ANY` in a signature, because placing the malicious file in an archive will then prevent it from alerting.

  Every ClamAV file type has the potential to be a container for additional files, although some are more likely than others. When a file is parsed and data in the file is identified to be scanned as a unique type, that parent file becomes a container the moment the embedded content is scanned. For a list of possible CL_TYPEs, refer to the [File Types Reference](ClamAVFileTypes.md).

- `Intermediates:CL_TYPE_*>CL_TYPE_*`: Specify one or more layers of file types containing the scanned file. _This is an alternative to using `Container`._

  You may specify up to 16 layers of file types separated by ’`>`’ in top-down order. Note that the ’`>`’ separator is not needed if you only specify a single container. The last type should be the immediate container containing the malicious file. Unlike with the `Container` option, `CL_TYPE_ANY` can be used as a wildcard file type. (expr; 0.100.0)

  For a list of possible CL_TYPEs, refer to the [File Types Reference](ClamAVFileTypes.md).

- `IconGroup1`: Icon group name 1 from .idb signature Required engine functionality (range; 0.96)

- `IconGroup2`: Icon group name 2 from .idb signature Required engine functionality (range; 0.96)

Modifiers for subexpressions:

- `A=X`: If the SUB-EXPRESSION A refers to a single signature then this signature must get matched exactly X times; if it refers to a (logical) block of signatures then this block must generate exactly X matches (with any of its sigs).

- `A=0` specifies negation (signature or block of signatures cannot be matched)

- `A=X,Y`: If the SUB-EXPRESSION A refers to a single signature then this signature must be matched exactly X times; if it refers to a (logical) block of signatures then this block must generate X matches and at least Y different signatures must get matched.

- `A>X`: If the SUB-EXPRESSION A refers to a single signature then this signature must get matched more than X times; if it refers to a (logical) block of signatures then this block must generate more than X matches (with any of its sigs).

- `A>X,Y`: If the SUB-EXPRESSION A refers to a single signature then this signature must get matched more than X times; if it refers to a (logical) block of signatures then this block must generate more than X matches _and_ at least Y different signatures must be matched.

- `A<X`: Just like `A>Z` above with the change of "more" to "less".

  If the SUB-EXPRESSION A refers to a single signature then this signature must get matched less than X times; if it refers to a (logical) block of signatures then this block must generate less than X matches (with any of its sigs).

- `A<X,Y`: Similar to `A>X,Y`. If the SUB-EXPRESSION A refers to a single signature then this signature must get matched less than X times; if it refers to a (logical) block of signatures then this block must generate less than X matches _and_ at least Y different signatures must be matched.

Examples:

```
Sig1;Target:0;(0&1&2&3)&(4|1);6b6f74656b;616c61;7a6f6c77;7374656
6616e;deadbeef

Sig2;Target:0;((0|1|2)>5,2)&(3|1);6b6f74656b;616c61;7a6f6c77;737
46566616e

Sig3;Target:0;((0|1|2|3)=2)&(4|1);6b6f74656b;616c61;7a6f6c77;737
46566616e;deadbeef

Sig4;Engine:51-255,Target:1;((0|1)&(2|3))&4;EP+123:33c06834f04100
f2aef7d14951684cf04100e8110a00;S2+78:22??232c2d252229{-15}6e6573
(63|64)61706528;S3+50:68efa311c3b9963cb1ee8e586d32aeb9043e;f9c58
dcf43987e4f519d629b103375;SL+550:6300680065005c0046006900
```

## Subsignature Modifiers

ClamAV (clamav-0.99) supports a number of additional subsignature
modifiers for logical signatures. This is done by specifying `::`
followed by a number of characters representing the desired options.
Signatures using subsignature modifiers require `Engine:81-255` for
backwards-compatibility.

- Case-Insensitive \[`i`\]

  Specifying the `i` modifier causes ClamAV to match all alphabetic hex bytes as case-insensitive. All patterns in ClamAV are case-sensitive by default.

- Wide \[`w`\]

  Specifying the `w` causes ClamAV to match all hex bytes encoded with two bytes per character. Note this simply interweaves each character with NULL characters and does not truly support UTF-16 characters. Wildcards for ’wide’ subsignatures are not treated as wide (i.e. there can be an odd number of intermittent characters). This can be combined with `a` to search for patterns in both wide and ascii.

- Fullword \[`f`\]

  Match subsignature as a fullword (delimited by non-alphanumeric characters).

- Ascii \[`a`\]

  Match subsignature as ascii characters. This can be combined with `w` to search for patterns in both ascii and wide.

Examples:

```
clamav-nocase-A;Engine:81-255,Target:0;0&1;41414141::i;424242424242::i
    -matches 'AAAA'(nocase) and 'BBBBBB'(nocase)

clamav-fullword-A;Engine:81-255,Target:0;0&1;414141;68656c6c6f::f
    -matches 'AAA' and 'hello'(fullword)
clamav-fullword-B;Engine:81-255,Target:0;0&1;414141;68656c6c6f::fi
    -matches 'AAA' and 'hello'(fullword nocase)

clamav-wide-B2;Engine:81-255,Target:0;0&1;414141;68656c6c6f::wa
    -matches 'AAA' and 'hello'(wide ascii)
clamav-wide-C0;Engine:81-255,Target:0;0&1;414141;68656c6c6f::iwfa
    -matches 'AAA' and 'hello'(nocase wide fullword ascii)
```

## Special Subsignature Types

### Macro subsignatures

Introduced in ClamAV 0.96

Format: `${min-max}MACROID$`

Macro subsignatures are used to combine a number of existing extended
signatures (`.ndb`) into a on-the-fly generated alternate string logical
signature (`.ldb`). Signatures using macro subsignatures require
`Engine:51-255` for backwards-compatibility.

Example:

```
      test.ldb:
        TestMacro;Engine:51-255,Target:0;0&1;616161;${6-7}12$

      test.ndb:
        D1:0:$12:626262
        D2:0:$12:636363
        D3:0:$30:626264
```

The example logical signature `TestMacro` is functionally equivalent
to:

```
`TestMacro;Engine:51-255,Target:0;0;616161{3-4}(626262|636363)`
```

- `MACROID` points to a group of signatures; there can be at most 32 macro groups.

  - In the example, `MACROID` is `12` and both `D1` and `D2` are members of macro group `12`. `D3` is a member of separate macro group `30`.

- `{min-max}` specifies the offset range at which one of the group signatures should match; the offset range is relative to the starting offset of the preceding subsignature. This means a macro subsignature cannot be the first subsignature.

  - In the example, `{min-max}` is `{6-7}` and it is relative to the start of a `616161` match.

- For more information and examples please see <https://bugzilla.clamav.net/show_bug.cgi?id=164>.

### Byte Compare Subsignatures

Introduced in ClamAV 0.101

Format: `subsigid_trigger(offset#byte_options#comparisons)`

Byte compare subsignatures can be used to evaluate a numeric value at a given offset from the start of another (matched) subsignature within the same logical signature. These are executed after all other subsignatures within the logical subsignature are fired, with the exception of PCRE subsignatures. They can evaluate offsets only from a single referenced subsignature, and that subsignature must give a valid match for the evaluation to occur.

- `subsigid_trigger` is a required field and may refer to any single non-PCRE, non-Byte Compare subsignature within the lsig. The byte compare subsig will evaluate if `subsigid_trigger` matches. Triggering on multiple subsigs or logic based triggering is not currently supported.

- `offset` is a required field that consists of an `offset_modifier` and a numeric `offset` (hex or decimal offsets are okay).

  - `offset_modifier` can be either `>>` or `<<` where the former denotes a positive offset and the latter denotes a negative offset. The offset is calculated from the start of `subsigid_trigger`, which allows for byte extraction before the specified match, after the match, and within the match itself.

  - `offset` must be a positive hex or decimal value. This will be the number of bytes from the start of the referenced `subsigid_trigger` match within the file buffer to begin the comparison.

- `byte_options` are used to specify the numeric type and endianess of the extracted byte sequence in that order as well as the number of bytes to be read. By default ClamAV will attempt to matchup up to the number of byte specified, unless the `e` (exact) option is specified or the numeric type is `b` (binary).  This field follows the form `[h|d|a|i][l|b][e]num_bytes`

  - `h|d|a|i` where `h` specifies the byte sequence will be in hex, `d` decimal, `a` automatic detection of hex or decimal at runtime, and `i` signifies raw binary data.

  - `l|b` where `l` specifies the byte sequence will be in little endian order and `b` big endian. If decimal `d` is specified, big-endian is implied and using `l` will result in a malformed database error.

  - `e` specifies that ClamAV will only evaluate the comparison if it can extract the exact number of bytes specified. This option is implicitly declared when using the `i` flag.

  - `num_bytes` specifies the number of bytes to extract. This can be a hex or decimal value. If `i` is specified only 1, 2, 4, and 8 are valid options.

- `comparisons` are a required field which denotes how to evaluate the extracted byte sequence. Each Byte Compare signature can have one or two `comparison_sets` separated by a comma. Each `comparison_set` consists of a `Comparison_symbol` and a `Comparison_value` and takes the form `Comparison_symbolComparison_value`. Thus, `comparisons` takes the form `comparison_set[,comparison_set]`

  - `Comparison_symbol` denotes the type of comparison to be done. The supported comparison symbols are `<`, `>`, `=`.

  - `Comparison_value` is a required field which must be a numeric hex or decimal value. If all other conditions are met, the byte compare subsig will evalutate the extracted byte sequence against this number based on the provided `comparison_symbol`.

### PCRE subsignatures

Introduced in ClamAV 0.99

Format: `Trigger/PCRE/[Flags]`

PCRE subsignatures are used within a logical signature (`.ldb`) to specify regex matches that execute once triggered by a conditional based on preceding subsignatures. Signatures using PCRE subsignatures require `Engine:81-255` for backwards-compatibility.

- `Trigger` is a required field that is a valid `LogicalExpression` and may refer to any subsignatures that precede this subsignature. Triggers cannot be self-referential and cannot refer to subsequent subsignatures.

- `PCRE` is the expression representing the regex to execute. `PCRE` must be delimited by ’/’ and usage of ’/’ within the expression need to be escaped. For backward compatibility, ’;’ within the expression must be expressed as ’`\x3B`’. `PCRE` cannot be empty and (?UTF\*) control sequence is not allowed. If debug is specified, named capture groups are displayed in a post-execution report.

- `Flags` are a series of characters which affect the compilation and execution of `PCRE` within the PCRE compiler and the ClamAV engine. This field is optional.

  - `g [CLAMAV_GLOBAL]` specifies to search for ALL matches of PCRE (default is to search for first match). NOTE: INCREASES the time needed to run the PCRE.

  - `r [CLAMAV_ROLLING]` specifies to use the given offset as the starting location to search for a match as opposed to the only location; applies to subsigs without maxshifts. By default, in order to facilatate normal ClamAV offset behavior, PCREs are auto-anchored (only attempt match on first offset); using the rolling option disables the auto-anchoring.

  - `e [CLAMAV_ENCOMPASS]` specifies to CONFINE matching between the specified offset and maxshift; applies only when maxshift is specified. Note: DECREASES time needed to run the PCRE.

  - `i [PCRE_CASELESS]`

  - `s [PCRE_DOTALL]`

  - `m [PCRE_MULTILINE]`

  - `x [PCRE_EXTENDED]`

  - `A [PCRE_ANCHORED]`

  - `E [PCRE_DOLLAR_ENODNLY]`

  - `U [PCRE_UNGREEDY]`

Examples:

```
Find.All.ClamAV;Engine:81-255,Target:0;1;6265676c6164697427736e6f7462797465636f6465;0/clamav/g

Find.ClamAV.OnlyAt.299;Engine:81-255,Target:0;2;7374756c747a67657473;7063726572656765786c6f6c;299:0&1/clamav/

Find.ClamAV.StartAt.300;Engine:81-255,Target:0;3;616c61696e;62756731393238;636c6f736564;300:0&1&2/clamav/r

Find.All.Encompassed.ClamAV;Engine:81-255,Target:0;3;7768796172656e2774;796f757573696e67;79617261;200,300:0&1&2/clamav/ge

Named.CapGroup.Pcre;Engine:81-255,Target:0;3;636f75727479617264;616c62756d;74657272696572;50:0&1&2/variable=(?<nilshell>.{16})end/gr

Firefox.TreeRange.UseAfterFree;Engine:81-255,Target:0,Engine:81-255;0&1&2;2e766965772e73656c656374696f6e;2e696e76616c696461746553656c656374696f6e;0&1/\x2Eview\x2Eselection.*?\x2Etree\s*\x3D\s*null.*?\x2Einvalidate/smi

Firefox.IDB.UseAfterFree;Engine:81-255,Target:0;0&1;4944424b657952616e6765;0/^\x2e(only|lowerBound|upperBound|bound)\x28.*?\x29.*?\x2e(lower|upper|lowerOpen|upperOpen)/smi

Firefox.boundElements;Engine:81-255,Target:0;0&1&2;6576656e742e6
26f756e64456c656d656e7473;77696e646f772e636c6f7365;0&1/on(load|click)\s*=\s*\x22?window\.close\s*\x28/si
```

## Signatures for Version Information (VI) metadata in PE files

Starting with ClamAV 0.96 it is possible to easily match certain information built into PE files (executables and dynamic link libraries). Whenever you lookup the properties of a PE executable file in windows, you are presented with a bunch of details about the file itself.

These info are stored in a special area of the file resources which goes under the name of `VS_VERSION_INFORMATION` (or versioninfo for short). It is divided into 2 parts. The first part (which is rather uninteresting) is really a bunch of numbers and flags indicating the product and file version. It was originally intended for use with installers which, after parsing it, should be able to determine whether a certain executable or library are to be upgraded/overwritten or are already up to date. Suffice to say, this approach never really worked and is generally never used.

The second block is much more interesting: it is a simple list of key/value strings, intended for user information and completely ignored by the OS. For example, if you look at ping.exe you can see the company being *"Microsoft Corporation"*, the description *"TCP/IP Ping command"*, the internal name *"ping.exe"* and so on... Depending on the OS version, some keys may be given peculiar visibility in the file properties dialog, however they are internally all the same.

To match a versioninfo key/value pair, the special file offset anchor `VI` was introduced. This is similar to the other anchors (like `EP` and `SL`) except that, instead of matching the hex pattern against a single offset, it checks it against each and every key/value pair in the file. The `VI` token doesn’t need nor accept a `+/-` offset like e.g. `EP+1`. As for the hex signature itself, it’s just the utf16 dump of the key and value. Only the `??` and `(aa|bb)` wildcards are allowed in the signature. Usually, you don’t need to bother figuring it out: each key/value pair together with the corresponding VI-based signature is printed by `clamscan` when the `--debug` option is given.

For example `clamscan --debug freecell.exe` produces:

```bash
[...]
Recognized MS-EXE/DLL file
in cli_peheader
versioninfo_cb: type: 10, name: 1, lang: 410, rva: 9608
cli_peheader: parsing version info @ rva 9608 (1/1)
VersionInfo (d2de): 'CompanyName'='Microsoft Corporation' -
VI:43006f006d00700061006e0079004e0061006d006500000000004d006900
630072006f0073006f0066007400200043006f00720070006f0072006100740
069006f006e000000
VersionInfo (d32a): 'FileDescription'='Entertainment Pack
FreeCell Game' - VI:460069006c006500440065007300630072006900700
0740069006f006e000000000045006e007400650072007400610069006e006d
0065006e00740020005000610063006b0020004600720065006500430065006
c006c002000470061006d0065000000
VersionInfo (d396): 'FileVersion'='5.1.2600.0 (xpclient.010817
-1148)' - VI:460069006c006500560065007200730069006f006e00000000
0035002e0031002e0032003600300030002e003000200028007800700063006
c00690065006e0074002e003000310030003800310037002d00310031003400
380029000000
VersionInfo (d3fa): 'InternalName'='freecell' - VI:49006e007400
650072006e0061006c004e0061006d006500000066007200650065006300650
06c006c000000
VersionInfo (d4ba): 'OriginalFilename'='freecell' - VI:4f007200
6900670069006e0061006c00460069006c0065006e0061006d0065000000660
0720065006500630065006c006c000000
VersionInfo (d4f6): 'ProductName'='Sistema operativo Microsoft
Windows' - VI:500072006f0064007500630074004e0061006d00650000000
000530069007300740065006d00610020006f00700065007200610074006900
76006f0020004d006900630072006f0073006f0066007400ae0020005700690
06e0064006f0077007300ae000000
VersionInfo (d562): 'ProductVersion'='5.1.2600.0' - VI:50007200
6f006400750063007400560065007200730069006f006e00000035002e00310
02e0032003600300030002e0030000000
[...]
```

Although VI-based signatures are intended for use in logical signatures you can test them using ordinary `.ndb` files. For example:

```
    my_test_vi_sig:1:VI:paste_your_hex_sig_here
```

Final note. If you want to decode a VI-based signature into a human readable form you can use:

```bash
echo hex_string | xxd -r -p | strings -el
```

For example:

```bash
$ echo 460069006c0065004400650073006300720069007000740069006f006e
000000000045006e007400650072007400610069006e006d0065006e007400200
05000610063006b0020004600720065006500430065006c006c00200047006100
6d0065000000 | xxd -r -p | strings -el
FileDescription
Entertainment Pack FreeCell Game
```

## Icon Signatures for PE files

While Icon Signatures are stored in a `.idb` file, they are a feature of Logical Signatures.

ClamAV 0.96 includes an approximate/fuzzy icon matcher to help detecting malicious executables disguising themselves as innocent looking image files, office documents and the like.

Icon matching is only triggered by Logical Signatures (`.ldb`) using the special attribute tokens `IconGroup1` or `IconGroup2`. These identify two (optional) groups of icons defined in a `.idb` database file. The format of the `.idb` file is:

```
    ICONNAME:GROUP1:GROUP2:ICON_HASH
```

where:

- `ICON_NAME` is a unique string identifier for a specific icon,

- `GROUP1` is a string identifier for the first group of icons (`IconGroup1`)

- `GROUP2` is a string identifier for the second group of icons (`IconGroup2`),

- `ICON_HASH` is a fuzzy hash of the icon image

The `ICON_HASH` field can be obtained from the debug output of libclamav. For example:

```bash
LibClamAV debug: ICO SIGNATURE:
ICON_NAME:GROUP1:GROUP2:18e2e0304ce60a0cc3a09053a30000414100057e000afe0000e 80006e510078b0a08910d11ad04105e0811510f084e01040c080a1d0b0021000a39002a41
```
