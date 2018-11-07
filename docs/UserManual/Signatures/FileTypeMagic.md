# File Type Magic

ClamAV's primary mechanism for determining file types is to match the file with a File Type Magic signature. These file type signatures are compiled into ClamAV, and may also be overridden dynamically using the definition founds found in a `*.ftm` file.

The ClamAV standard signature database includes these definitions in `daily.ftm`.

The signature format is not too disimilar from NDB body-based signatures.

The format is:

```
    magictype:offset:magicbytes:name:type:type[:min_flevel[:max_flevel]]
```

Where:

`magictype`: Supported magic types include:

* 0 - direct memory comparison of `magicbytes` for file types
* 1 - The `magicbytes` use the body-based content matching [format](BodySignatureFormat.md).
* 4 - direct memory comparison of `magicbytes` for partition types (HFS+, HFSX)

`offset`: The offset from start of the file to match against.  May be `*` if `magictype` is 1.

`name`: A descriptive name for the file type.

`rtype`: Usually CL_TYPE_ANY.

`type`: The CL_TYPE corresponding with the file type signature. See the [CL_TYPE reference](ClamAVFileTypes.md) for details.

`min_flevel`: (optional) The minimum ClamAV engine that the file type signature works with. See the [FLEVEL reference](FunctionalityLevels.md) for details. To be used in the event that file type support has been recently added.

`max_flevel`: (optional, requires `min_flevel`) The maximum ClamAV engine that the file type signature works with. To be used in the event that file type support has been recently removed.
