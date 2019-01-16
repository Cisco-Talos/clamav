# Passwords for archive files \[experimental\]

ClamAV 0.99 allows for users to specify password attempts for certain password-compatible archives. Passwords will be attempted in order of appearance in the password signature file which use the extension of `.pwdb`. If no passwords apply or none are provided, ClamAV will default to the original behavior of parsing the file. Currently, as of ClamAV 0.99 \[flevel 81\], only `.zip` archives using the traditional PKWARE encryption are supported. The signature format is

```
SignatureName;TargetDescriptionBlock;PWStorageType;Password
```

where:

- `SignatureName`: name to be displayed during debug when a password is successful

- `TargetDescriptionBlock`: provides information about the engine and target file with comma separated Arg:Val pairs
  - `Engine:X-Y`: Required engine functionality level. See the [FLEVEL reference](FunctionalityLevels.md) for details.
  - `Container:CL_TYPE_*`: File type of applicable containers

- `PWStorageType`: determines how the password field is parsed
  - 0 = cleartext
  - 1 = hex

- `Password`: value used in password attempt

The signatures for password attempts are stored inside `.pwdb` files.
