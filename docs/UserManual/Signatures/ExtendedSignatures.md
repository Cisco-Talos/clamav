# Extended signature format

The extended signature format is ClamAV's most basic type of body-based signature since the deprecation of the original `.db` database format.

Extended sigantures allow for specification of additional information beyond just hexidecimal content such as a file "target type", virus offset, or engine functionality level (FLEVEL), making the detection more reliable.

The format is:

```
    MalwareName:TargetType:Offset:HexSignature[:min_flevel:[max_flevel]]
```

`MalwareName`: The virus name. Should conform to the standards defined [here](../Signatures.md#Signature-names).

`TargetType`: A number specifying the type of the target file: [Target Types](FileTypes.md#Target-Types)

`Offset`: An asterisk or a decimal number `n` possibly combined with a special modifier:

- `*` = any
- `n` = absolute offset
- `EOF-n` = end of file minus `n` bytes

Signatures for PE, ELF and Mach-O files additionally support:

- `EP+n` = entry point plus n bytes (`EP+0` for `EP`)
- `EP-n` = entry point minus n bytes
- `Sx+n` = start of section `x`’s (counted from 0) data plus `n` bytes
- `SEx` = entire section `x` (offset must lie within section boundaries)
- `SL+n` = start of last section plus `n` bytes

All the above offsets except `*` can be turned into **floating offsets** and represented as `Offset,MaxShift` where `MaxShift` is an unsigned integer. A floating offset will match every offset between `Offset` and `Offset+MaxShift`, eg. `10,5` will match all offsets from 10 to 15 and `EP+n,y` will match all offsets from `EP+n` to `EP+n+y`. Versions of ClamAV older than 0.91 will silently ignore the `MaxShift` extension and only use `Offset`. Optional `MinFL` and `MaxFL` parameters can restrict the signature to specific engine releases. All signatures in the extended format must be placed inside `*.ndb` files.

`HexSignature`: The body-based content matching [format](BodySignatureFormat.md).

`min_flevel`: (optional) The minimum ClamAV engine that the file type signature works with. See the [FLEVEL reference](FunctionalityLevels.md) for details. To be used in the event that file type support has been recently added.

`max_flevel`: (optional, requires `min_flevel`) The maximum ClamAV engine that the file type signature works with. To be used in the event that file type support has been recently removed.
