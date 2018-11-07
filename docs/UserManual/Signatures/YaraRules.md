# Using YARA rules in ClamAV

ClamAV version 0.99 and above can process YARA rules. ClamAV virus database file names ending with “.yar” or “.yara” are parsed as yara rule files. The link to the YARA rule grammar documentation may be found at http://plusvic.github.io/yara/. There are currently a few limitations on using YARA rules within ClamAV:

- YARA modules are not yet supported by ClamAV. This includes the “import” keyword and any YARA module-specific keywords.

- Global rules(“global” keyword) are not supported by ClamAV.

- External variables(“contains” and “matches” keywords) are not supported.

- YARA rules pre-compiled with the *yarac* command are not supported.

- As in the ClamAV logical and extended signature formats, YARA strings and segments of strings separated by wild cards must represent at least two octets of data.

- There is a maximum of 64 strings per YARA rule.

- YARA rules in ClamAV must contain at least one literal, hexadecimal, or regular expression string.

In addition, there are a few more ClamAV processing modes that may affect the outcome of YARA rules.

- *File decomposition and decompression* - Since ClamAV uses file decomposition and decompression to find viruses within de-archived and uncompressed inner files, YARA rules executed by ClamAV will match against these files as well.

- *Normalization* - By default, ClamAV normalizes HTML, JavaScript, and ASCII text files. YARA rules in ClamAV will match against the normalized result. The effects of normalization of these file types may be captured using `clamscan --leave-temps --tempdir=mytempdir`. YARA rules may then be written using the normalized file(s) found in `mytempdir`. Alternatively, starting with ClamAV 0.100.0, `clamscan --normalize=no` will prevent normalization and only scan the raw file. To obtain similar behavior prior to 0.99.2, use `clamscan --scan-html=no`. The corresponding parameters for clamd.conf are `Normalize` and `ScanHTML`.

- *YARA conditions driven by string matches* - All YARA conditions are driven by string matches in ClamAV. This saves from executing every YARA rule on every file. Any YARA condition may be augmented with a string match clause which is always true, such as:

```yara
  rule CheckFileSize
  {
    strings:
      $abc = "abc"
    condition:
      ($abc or not $abc) and filesize < 200KB
  }
```

This will ensure that the YARA condition always performs the desired action (checking the file size in this example),
