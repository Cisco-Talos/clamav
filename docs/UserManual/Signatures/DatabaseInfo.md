# Database Info

The `.info` file format specifies information about the other database files unpacked from a CVD or CLD database archive. This file exists for the purposes of validating the correctness of the official ClamAV database container files and cannot be loaded a la carte.

The format is simply:

```
name:size:sha256
```

`name`: The database file name.

`size`: The size in bytes of the database.

`sha256`: A SHA256 hash of the database.
