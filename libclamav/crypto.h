/*
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#if !defined(_CLAMAV_CRYPTO_H)
#define _CLAMAV_CRYPTO_H

/**
 * \defgroup CryptoAPI ClamAV Crypto API
 * @{
 */

#define SHA1_HASH_SIZE 20
#define SHA256_HASH_SIZE 32

/**
 * Initialize the crypto system.
 * @return Always returns 0
 */
int cl_initialize_crypto(void);

/** Clean up the crypto system prior to program exit.
 */
void cl_cleanup_crypto(void);

/** Generate a hash of data.
 @param[in] alg The hashing algorithm to use
 @param[in] buf The data to be hashed
 @param[in] len The length of the to-be-hashed data
 @param[out] obuf An optional buffer to store the generated hash. Use NULL to dynamically allocate buffer.
 @param[out] olen An optional pointer that stores how long the generated hash is.
 @return A pointer to the generated hash or obuf if obuf is not NULL.
 */
unsigned char *cl_hash_data(char *alg, const void *buf, size_t len, unsigned char *obuf, unsigned int *olen);

/** Generate a hash of a file.
 @param[in] ctx A pointer to the OpenSSL EVP_MD_CTX object
 @param[in] fd The file descriptor
 @param[out] olen An optional pointer that stores how long the generated hash is
 @return A pointer to a dynamically-created buffer that holds the generated hash
 */
unsigned char *cl_hash_file_fd_ctx(EVP_MD_CTX *ctx, int fd, unsigned int *olen);

/** Generate a hash of a file.
 @param[in] fd The file descriptor
 @param[in] alg The hashing algorithm to use
 @param[out] olen An optional pointer that stores how long the generated hash is
 @return A pointer to a dynamically-created buffer that holds the generated hash
 */
unsigned char *cl_hash_file_fd(int fd, char *alg, unsigned int *olen);

/** Generate a hash of a file.
 @param[in] fp A pointer to a FILE object
 @param[in] alg The hashing algorithm to use
 @param[out] olen An optional pointer that stores how long the generated hash is
 @return A pointer to a dynamically-created buffer that holds the generated hash
 */
unsigned char *cl_hash_file_fp(FILE *fp, char *alg, unsigned int *olen);

/** Generate a sha256 hash of data
 @param[in] buf The data to hash
 @param[in] len The length of the to-be-hashed data
 @param[out] obuf An optional pointer to store the generated hash. Use NULL to dynamically allocate buffer.
 @param[out] olen An optional pointer that stores how long the generated hash is.
 @return A pointer to the buffer that holds the generated hash
 */
unsigned char *cl_sha256(const void *buf, size_t len, unsigned char *obuf, unsigned int *olen);

/** Generate a sha1 hash of data
 @param[in] buf The data to hash
 @param[in] len The length of the to-be-hashed data
 @param[out] obuf An optional pointer to store the generated hash. Use NULL to dynamically allocate buffer.
 @param[out] olen An optional pointer that stores how long the generated hash is.
 @return A pointer to the buffer that holds the generated hash or obuf if obuf is not NULL
 */
unsigned char *cl_sha1(const void *buf, size_t len, unsigned char *obuf, unsigned int *olen);

/** Verify validity of signed data
 @param[in] pkey The public key of the keypair that signed the data
 @param[in] alg The algorithm used to hash the data
 @param[in] sig The signature block
 @param[in] siglen The length of the signature
 @param[in] data The data that was signed
 @param[in] datalen The length of the data
 @param[in] decode Whether or not to base64-decode the signature prior to verification. 1 for yes, 0 for no.
 @return 0 for success, -1 for error or invalid signature
 */
int cl_verify_signature(EVP_PKEY *pkey, char *alg, unsigned char *sig, unsigned int siglen, unsigned char *data, size_t datalen, int decode);

/** Verify validity of signed data
 @param[in] pkey The public key of the keypair that signed the data
 @param[in] alg The algorithm used to hash the data
 @param[in] sig The signature block
 @param[in] siglen The length of the signature
 @param[in] digest The hash of the signed data
 @return 0 for success, -1 for error or invalid signature
 */
int cl_verify_signature_hash(EVP_PKEY *pkey, char *alg, unsigned char *sig, unsigned int siglen, unsigned char *digest);

/** Verify validity of signed data
 @param[in] pkey The public key of the keypair that signed the data
 @param[in] alg The algorithm used to hash the data
 @param[in] sig The signature block
 @param[in] siglen The length of the signature
 @param[in] fd The file descriptor
 @return 0 for success, -1 for error or invalid signature
 */
int cl_verify_signature_fd(EVP_PKEY *pkey, char *alg, unsigned char *sig, unsigned int siglen, int fd);

/** Verify validity of signed data
 @param[in] x509path The path to the public key of the keypair that signed the data
 @param[in] alg The algorithm used to hash the data
 @param[in] sig The signature block
 @param[in] siglen The length of the signature
 @param[in] digest The hash of the signed data
 @return 0 for success, -1 for error or invalid signature
 */
int cl_verify_signature_hash_x509_keyfile(char *x509path, char *alg, unsigned char *sig, unsigned int siglen, unsigned char *digest);

/** Verify validity of signed data
 @param[in] x509path The path to the public key of the keypair that signed the data
 @param[in] alg The algorithm used to hash the data
 @param[in] sig The signature block
 @param[in] siglen The length of the signature
 @param[in] fd The file descriptor
 @return 0 for success, -1 for error or invalid signature
 */
int cl_verify_signature_fd_x509_keyfile(char *x509path, char *alg, unsigned char *sig, unsigned int siglen, int fd);

/** Verify validity of signed data
 @param[in] x509path The path to the public key of the keypair that signed the data
 @param[in] alg The algorithm used to hash the data
 @param[in] sig The signature block
 @param[in] siglen The length of the signature
 @param[in] data The data that was signed
 @param[in] datalen The length of the data
 @param[in] decode Whether or not to base64-decode the signature prior to verification. 1 for yes, 0 for no.
 @return 0 for success, -1 for error or invalid signature
 */
int cl_verify_signature_x509_keyfile(char *x509path, char *alg, unsigned char *sig, unsigned int siglen, unsigned char *data, size_t datalen, int decode);

/** Verify validity of signed data
 @param[in] x509 The X509 object of the public key of the keypair that signed the data
 @param[in] alg The algorithm used to hash the data
 @param[in] sig The signature block
 @param[in] siglen The length of the signature
 @param[in] digest The hash of the signed data
 @return 0 for success, -1 for error or invalid signature
 */
int cl_verify_signature_hash_x509(X509 *x509, char *alg, unsigned char *sig, unsigned int siglen, unsigned char *digest);

/** Verify validity of signed data
 @param[in] x509 The X509 object of the public key of the keypair that signed the data
 @param[in] alg The algorithm used to hash the data
 @param[in] sig The signature block
 @param[in] siglen The length of the signature
 @param[in] fd The file descriptor
 @return 0 for success, -1 for error or invalid signature
 */
int cl_verify_signature_fd_x509(X509 *x509, char *alg, unsigned char *sig, unsigned int siglen, int fd);

/** Verify validity of signed data
 @param[in] x509 The X509 object of the public key of the keypair that signed the data
 @param[in] alg The algorithm used to hash the data
 @param[in] sig The signature block
 @param[in] siglen The length of the signature
 @param[in] data The data that was signed
 @param[in] datalen The length of the data
 @param[in] decode Whether or not to base64-decode the signature prior to verification. 1 for yes, 0 for no.
 @return 0 for success, -1 for error or invalid signature
 */
int cl_verify_signature_x509(X509 *x509, char *alg, unsigned char *sig, unsigned int siglen, unsigned char *data, size_t datalen, int decode);

/** Get an X509 object from memory
 * @param[in] data A pointer to a spot in memory that contains the PEM X509 cert
 * @param[in] len The length of the data
 * @return a pointer to the X509 object on success, NULL on error
 */
X509 *cl_get_x509_from_mem(void *data, unsigned int len);

/** Validate an X509 certificate chain, with the chain being located in a directory
 @param[in] tsdir The path to the trust store directory
 @param[in] certpath The path to the X509 certificate to be validated.
 @return 0 for success, -1 for error or invalid certificate.
 */
int cl_validate_certificate_chain_ts_dir(char *tsdir, char *certpath);

/** Validate an X509 certificate chain with support for a CRL
 @param[in] authorities A NULL-terminated array of strings that hold the path of the CA's X509 certificate
 @param[in] crlpath An optional path to the CRL file. NULL if no CRL.
 @param[in] certpath The path to the X509 certificate to be validated.
 @return 0 for success, -1 for error or invalid certificate.
 */
int cl_validate_certificate_chain(char **authorities, char *crlpath, char *certpath);

/** Load an X509 certificate from a file
 @param[in] certpath The path to the X509 certificate
 */
X509 *cl_load_cert(const char *certpath);

/** Parse an ASN1_TIME object
 @param[in] timeobj The ASN1_TIME object
 @return A pointer to a (struct tm). Adjusted for time zone and daylight savings time.
 */
struct tm *cl_ASN1_GetTimeT(ASN1_TIME *timeobj);

/** Load a CRL file into an X509_CRL object
 @param[in] file The path to the CRL
 @return A pointer to an X509_CRL object or NULL on error.
 */
X509_CRL *cl_load_crl(const char *timeobj);

/** Sign data with a key stored on disk
 @param[in] keypath The path to the RSA private key
 @param[in] alg The hash/signature algorithm to use
 @param[in] hash The hash to sign
 @param[out] olen A pointer that stores the size of the signature
 @param[in] Whether or not to base64-encode the signature. 1 for yes, 0 for no.
 @return The generated signature
 */
unsigned char *cl_sign_data_keyfile(char *keypath, char *alg, unsigned char *hash, unsigned int *olen, int encode);

/** Sign data with an RSA private key object
 @param[in] pkey The RSA private key object
 @param[in] alg The hash/signature algorithm to use
 @param[in] hash The hash to sign
 @param[out] olen A pointer that stores the size of the signature
 @param[in] Whether or not to base64-encode the signature. 1 for yes, 0 for no.
 @return The generated signature
 */
unsigned char *cl_sign_data(EVP_PKEY *pkey, char *alg, unsigned char *hash, unsigned int *olen, int encode);

/** Sign a file with an RSA private key object
 @param[in] fd The file descriptor
 @param[in] pkey The RSA private key object
 @param[in] alg The hash/signature algorithm to use
 @param[out] olen A pointer that stores the size of the signature
 @param[in] encode Whether or not to base64-encode the signature. 1 for yes, 0 for no.
 */
unsigned char *cl_sign_file_fd(int fd, EVP_PKEY *pkey, char *alg, unsigned int *olen, int encode);

/** Sign a file with an RSA private key object
 @param[in] fp A pointer to a FILE object
 @param[in] pkey The RSA private key object
 @param[in] alg The hash/signature algorithm to use
 @param[out] olen A pointer that stores the size of the signature
 @param[in] encode Whether or not to base64-encode the signature. 1 for yes, 0 for no.
 */
unsigned char *cl_sign_file_fp(FILE *fp, EVP_PKEY *pkey, char *alg, unsigned int *olen, int encode);

/** Get the Private Key stored on disk
 * @param[in] keypath The path on disk where the private key is stored
 * @return A pointer to the EVP_PKEY object that contains the private key in memory
 */
EVP_PKEY *cl_get_pkey_file(char *keypath);

void *cl_hash_init(const char *alg);
int cl_update_hash(void *ctx, void *data, size_t sz);
int cl_finish_hash(void *ctx, void *buf);
void cl_hash_destroy(void *ctx);

/**
 * @}
 */

#endif
