# Trusted and Revoked Certificates

Clamav 0.98 checks signed PE files for certificates and verifies each certificate in the chain against a database of trusted and revoked certificates. The signature format is

```
    Name;Trusted;Subject;Serial;Pubkey;Exponent;CodeSign;TimeSign;CertSign;
    NotBefore;Comment[;minFL[;maxFL]]
```

where the corresponding fields are:

- `Name:` name of the entry

- `Trusted:` bit field, specifying whether the cert is trusted. 1 for trusted. 0 for revoked

- `Subject:` sha1 of the Subject field in hex

- `Serial:` the serial number as clamscan –debug –verbose reports

- `Pubkey:` the public key in hex

- `Exponent:` the exponent in hex. Currently ignored and hardcoded to 010001 (in hex)

- `CodeSign:` bit field, specifying whether this cert can sign code. 1 for true, 0 for false

- `TimeSign:` bit field. 1 for true, 0 for false

- `CertSign:` bit field, specifying whether this cert can sign other certs. 1 for true, 0 for false

- `NotBefore:` integer, cert should not be added before this variable. Defaults to 0 if left empty

- `Comment:` comments for this entry

The signatures for certs are stored inside `.crb` files.
