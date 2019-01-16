# Whitelist databases

## File whitelists

To whitelist a specific file use the MD5 signature format and place it inside a database file with the extension of `.fp`. To whitelist a specific file with the SHA1 or SHA256 file hash signature format, place the signature inside a database file with the extension of `.sfp`.

## Signature whitelists

To whitelist a specific signature from the database you just add the signature name into a local file with the `.ign2` extension and store it inside the database directory.

E.g:

```
    Eicar-Test-Signature
```

Additionally, you can follow the signature name with the MD5 of the entire database entry for this signature. In such a case, the signature will no longer be whitelisted when its entry in the database gets modified (eg. the signature gets updated to avoid false alerts). E.g:

```
    Eicar-Test-Signature:bc356bae4c42f19a3de16e333ba3569c
```

Historically, signature whitelists were added to `.ign` files.  This format is still functional, though it has been replaced by the `.ign2` database.
