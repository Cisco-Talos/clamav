# Dynamic Configuration (DCONF)

ClamAV supports a limited set of configuration options that may be enabled or disabled via settings in the `*.cfg` database. At this time, these settings are distributed in `daily.cfg`.

The goal of DCONF is to enable the ClamAV team to rapidly disable new or experimental features for specific ClamAV versions if a significant defect is discovered after release.

This database is small, and the settings are largely vestigial. The team has not had a need to disable many features in a long time, and so the ClamAV versions in the settings at this time should no longer be in use.

The strings and values referenced in `daily.cfg` are best cross-referenced with the macros and structures defined here:

* https://github.com/Cisco-Talos/clamav-devel/blob/dev/0.101/libclamav/dconf.h#L49
* https://github.com/Cisco-Talos/clamav-devel/blob/dev/0.101/libclamav/dconf.c#L54

The format for a DCONF signature is:

```
Category:Flags:StartFlevel:EndFlevel
```

`Category` may be one of:

* PE
* ELF
* MACHO
* ARCHIVE
* DOCUMENT
* MAIL
* OTHER
* PHISHING
* BYTECODE
* STATS
* PCRE

`Flags`:

Every feature that may be configured via DCONF is listed in `struct dconf_module modules` in `libclamav/dconf.c`. Any given feature may be default-on or default-off. Default-on features have the 4th field set to a `1` and default off are set to `0`. The `Flags` field for a given `Category` overrides the defaults for all of the options listed under that category. 

A settings of `0x0`, for example, means that all options the category be disabled.

The macros listed in `libclamav/dconf.h` will help you identify which bits to set to get the desired results.

`StartFlevel`:

This is the [FLEVEL](FunctionalityLevels.md) of the minimum ClamAV engine for which you want the settings to be in effect.

`EndFlevel`:

This is the [FLEVEL](FunctionalityLevels.md) of the maximum ClamAV engine for which you want the settings to be in effect.  You may wish to select `255` to override the defaults of future releases.

## Example

Consider the `OTHER_CONF_PDFNAMEOBJ` option in the `category` `OTHER`.

```c
#define OTHER_CONF_UUENC        0x1     // Default: 1
#define OTHER_CONF_SCRENC       0x2     // Default: 1
#define OTHER_CONF_RIFF         0x4     // Default: 1
#define OTHER_CONF_JPEG         0x8     // Default: 1
#define OTHER_CONF_CRYPTFF      0x10    // Default: 1
#define OTHER_CONF_DLP          0x20    // Default: 1
#define OTHER_CONF_MYDOOMLOG    0x40    // Default: 1
#define OTHER_CONF_PREFILTERING 0x80    // Default: 1
#define OTHER_CONF_PDFNAMEOBJ   0x100   // Default: 1
#define OTHER_CONF_PRTNINTXN    0x200   // Default: 1
#define OTHER_CONF_LZW          0x400   // Default: 1
```

All of the `OTHER` options, including `OTHER_CONF_PDFNAMEOBJ` are default-on. To disable the option for ClamAV v0.100.X but leave the other options in their default settings, we would need to set the flags to:

```binary
0110 1111 1111
   ^pdfnameobj off
```

Or in hex: `0x6FF`

The example setting to place in `daily.cfg` then woudl be:

```
OTHER:0x6FF:90:99
```
