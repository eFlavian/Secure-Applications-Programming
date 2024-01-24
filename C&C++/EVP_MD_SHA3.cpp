#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define HANDLE_ERROR(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define HANDLE_ERROR2(msg, mdctx) { fprintf(stderr, "%s\n", msg); EVP_MD_CTX_destroy(mdctx); exit(EXIT_FAILURE); }

int main(int argc, char* const argv[]) {
    // Input data to be hashed
    unsigned char buffer[] = { 0x2b, 0xbb, 0x42, 0xb9, 0x20, 0xb7, 0xfe, 0xb4,
                               0xe3, 0x96, 0x2a, 0x15, 0x52, 0xcc, 0x39, 0x0f };

    // Variables for OpenSSL
    EVP_MD_CTX* mdctx;
    unsigned char* digest;
    unsigned int digest_len;
    unsigned int digest_block_size;
    EVP_MD* algo = NULL;

    // Specify the hash algorithm (SHA3-512 in this case)
    algo = (EVP_MD*)EVP_sha3_512();

    // Create the message digest context
    if ((mdctx = EVP_MD_CTX_create()) == NULL) {
        HANDLE_ERROR("EVP_MD_CTX_create() error")
    }

    // Initialize the digest engine
    if (EVP_DigestInit_ex(mdctx, algo, NULL) != 1) { // Returns 1 if successful
        HANDLE_ERROR2("EVP_DigestInit_ex() error", mdctx)
    }

    // Update the digest context with input data
    if (EVP_DigestUpdate(mdctx, buffer, sizeof(buffer)) != 1) { // Returns 1 if successful
        HANDLE_ERROR2("EVP_DigestUpdate() error", mdctx)
    }

    // Obtain information about the hash algorithm
    digest_len = EVP_MD_size(algo);
    digest_block_size = EVP_MD_block_size(algo);

    // Allocate memory for the digest
    if ((digest = (unsigned char*)OPENSSL_malloc(digest_len)) == NULL) {
        HANDLE_ERROR2("OPENSSL_malloc() error", mdctx)
    }

    // Produce the final digest
    unsigned int sha3_length = 0;
    if (EVP_DigestFinal_ex(mdctx, digest, &sha3_length) != 1) { // Returns 1 if successful; sha3_length MUST be equal to digest_len
        OPENSSL_free(digest); // Free memory allocated for the digest
        HANDLE_ERROR2("EVP_DigestFinal_ex() error", mdctx)
    }

    // Print the resulting hash in hexadecimal format
    for (unsigned int i = 0; i < sha3_length; i++) {
        printf("%02x", digest[i]);
    }

    // Free allocated memory and destroy the digest context
    OPENSSL_free(digest);
    EVP_MD_CTX_destroy(mdctx);

    return 0;
}
