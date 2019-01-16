# Bytecode Signatures

Bytecode Signatures are the means by which more complex matching can be performed by writing C code to parse sample content at various stages in file extraction.

It is less complicated than it sounds. Essentially the signature author writes a function in C is compiled down to an intermediate language called "bytecode". This bytecode is encoded in ASCII `.cbc` file and distributed in `bytecode.[cvd|cld]`. When the database is loaded, ClamAV can interpret this bytecode to execute the function.

Bytecode functions are provided with a set of API's that may be used to access the sample data, and to access what metadata ClamAV already has concerning the sample.

The function may at any time call an API to flag the sample as malicious, and may provide the signature/virus name at that time. This means a single bytecode signature (function) is written to handle a given file type and may trigger different alerts with different signature names as additional malicious characteristics for the file type are identified. That isn't to say that only one bytecode signature may be assigned to a given filetype, but that a single author may find it to be more efficient to use a bytecode signature to identify more than one type of malware.

The specifics on how to write and compile bytecode signatures are outside of the scope of this documentation. Extensive documentation on ClamAV Bytecode Signatures are provided with the [ClamAV Bytecode Compiler](https://github.com/vrtadmin/clamav-bytecode-compiler).
