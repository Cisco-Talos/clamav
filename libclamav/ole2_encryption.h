#ifndef OLE2_ENCRYPTION_H_
#define OLE2_ENCRYPTION_H_

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

#define SE_HEADER_EI_AES128_KEYSIZE 0x00000080
#define SE_HEADER_EI_AES192_KEYSIZE 0x000000c0
#define SE_HEADER_EI_AES256_KEYSIZE 0x00000100

typedef struct {
    uint8_t key[SE_HEADER_EI_AES256_KEYSIZE]; /*The longest key length supported by ole encryption */
    uint32_t key_length_bits;
} encryption_key_t;

/* https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/dca653b5-b93b-48df-8e1e-0fb9e1c83b0f */
typedef struct __attribute__((packed)) {

    uint32_t flags;
    uint32_t sizeExtra; /* must be 0 */
    uint32_t algorithmID;
    uint32_t algorithmIDHash;
    uint32_t keySize;
    uint32_t providerType;
    uint32_t reserved1;
    uint32_t reserved2; /* MUST be 0 */

    // uint8_t cspName[variable]; /* really the rest of the data in the block.  Starts with a
    //                               string of wide characters, followed by the encryption verifier.
    //                               It is 44 instead of 32 because this structure is only used inside
    //                               encryption_info_stream_standard_t (below).  It is in two different
    //                               structures because of the way the documentation is written.
    //                               */

} encryption_info_t;

/*
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/2895eba1-acb1-4624-9bde-2cdad3fea015
 */
typedef struct __attribute__((packed)) {

    uint16_t version_major;
    uint16_t version_minor;
    uint32_t flags; /* https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/200a3d61-1ab4-4402-ae11-0290b28ab9cb */

    uint32_t size;

    encryption_info_t encryptionInfo;

} encryption_info_stream_standard_t;

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/e5ad39b8-9bc1-4a19-bad3-44e6246d21e6 */
typedef struct __attribute__((packed)) {
    uint32_t salt_size;
    uint8_t salt[16];
    uint8_t encrypted_verifier[16];
    uint32_t verifier_hash_size;
    uint8_t encrypted_verifier_hash[32]; /* RC4 requires 20 bytes
                                            AES requires 32 bytes
                                            */

} encryption_verifier_t;

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

#endif /* OLE2_ENCRYPTION_H_ */
