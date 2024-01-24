#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

int main(int argc, char** argv)
{
    if (argc == 3) {
        FILE* fsrc = NULL;
        FILE* fsig = NULL;
        errno_t err;
        SHA256_CTX ctx;

        // Step #1: Compute the message digest for the restored plaintext
        unsigned char finalDigest[SHA256_DIGEST_LENGTH];
        unsigned char* fileBuffer = NULL;
        SHA256_Init(&ctx);

        // Open the source file for reading in binary mode
        err = fopen_s(&fsrc, argv[1], "rb");
        fseek(fsrc, 0, SEEK_END);
        int fileLen = ftell(fsrc);
        fseek(fsrc, 0, SEEK_SET);

        // Allocate buffer to store file content
        fileBuffer = (unsigned char*)malloc(fileLen);
        fread(fileBuffer, fileLen, 1, fsrc);
        unsigned char* tmpBuffer = fileBuffer;

        // Update SHA-256 context with file content
        while (fileLen > 0) {
            if (fileLen > SHA256_DIGEST_LENGTH) {
                SHA256_Update(&ctx, tmpBuffer, SHA256_DIGEST_LENGTH);
            }
            else {
                SHA256_Update(&ctx, tmpBuffer, fileLen);
            }
            fileLen -= SHA256_DIGEST_LENGTH;
            tmpBuffer += SHA256_DIGEST_LENGTH;
        }

        // Finalize SHA-256 and obtain the digest
        SHA256_Final(finalDigest, &ctx);

        // Print the SHA-256 digest computed from the plaintext
        printf("\n SHA-256 content computed: ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            printf("%02X ", finalDigest[i]);
        printf("\n");

        fclose(fsrc);

        // Step #2: Decrypt the content of e-signature and compare it with the message digest from Step #1
        err = fopen_s(&fsig, argv[2], "rb");

        RSA* apub;
        FILE* f;
        unsigned char* buf = NULL;
        unsigned char* last_data = NULL;

        apub = RSA_new();

        // Load the RSA public key
        f = fopen("pubKeySender.pem", "r");
        apub = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
        fclose(f);

        // Allocate buffer for the ciphertext (e-signature)
        buf = (unsigned char*)malloc(RSA_size(apub));

        // Read the ciphertext from the e-signature file
        fread(buf, RSA_size(apub), 1, fsig);

        // Allocate buffer for the decrypted content
        last_data = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);

        // Decrypt the e-signature using the RSA public key
        RSA_public_decrypt(RSA_size(apub), buf, last_data, apub, RSA_PKCS1_PADDING);

        // Close the e-signature file
        fclose(fsig);

        // Print the decrypted SHA-256 content obtained from the e-signature file
        printf("\n SHA-256 content decrypted from digital signature file: ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            printf("%02X ", last_data[i]);
        printf("\n");

        // Compare the computed digest and decrypted digest
        if (memcmp(last_data, finalDigest, SHA256_DIGEST_LENGTH) == 0)
            printf("\n Signature OK!\n");
        else
            printf("\n Signature does not validate the message!\n");

        // Free allocated memory
        free(last_data);
        free(buf);

        // Free RSA key structure
        RSA_free(apub);
    }
    else {
        printf("\n Usage mode: OpenSSLProj.exe fSrc.txt eSignFsrc.txt");
        return 1;
    }

    return 0;
}
