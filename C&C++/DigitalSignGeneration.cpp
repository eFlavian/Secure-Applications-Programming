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
        FILE* fdst = NULL;
        errno_t err;
        SHA256_CTX ctx;

        // Variables to store the SHA-256 digest and the final digital signature
        unsigned char finalDigest[SHA256_DIGEST_LENGTH];
        unsigned char* fileBuffer = NULL;

        // Initialize SHA-256 context
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

        // Finalize SHA-256 and get the digest
        SHA256_Final(finalDigest, &ctx);

        // Print the SHA-256 digest
        printf("SHA(256) = ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            printf("%02X ", finalDigest[i]);
        printf("\n");

        fclose(fsrc);

        // Open the destination file for writing in binary mode
        err = fopen_s(&fdst, argv[2], "wb");

        RSA* apriv;
        FILE* f;

        unsigned char* buf = NULL;
        unsigned char* e_data = NULL;

        apriv = RSA_new();

        // Load the RSA private key
        f = fopen("privKeySender.pem", "r");
        apriv = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
        fclose(f);

        // Allocate buffer for the digital signature
        buf = (unsigned char*)malloc(sizeof(finalDigest));
        memcpy(buf, finalDigest, sizeof(finalDigest));

        // Allocate buffer for the digital signature (RSA block)
        e_data = (unsigned char*)malloc(RSA_size(apriv));

        // RSA private key encryption for digital signature
        RSA_private_encrypt(sizeof(finalDigest), buf, e_data, apriv, RSA_PKCS1_PADDING);

        // Print the digital signature
        printf("Signature(RSA) = ");
        printf("\n");
        for (int i = 0; i < RSA_size(apriv); i++) {
            printf("%02X ", e_data[i]);
        }
        printf("\n");

        // Write the digital signature to the destination file
        fwrite(e_data, RSA_size(apriv), 1, fdst);

        fclose(fdst);

        // Free allocated memory
        free(e_data);
        free(buf);

        // Free RSA key structure
        RSA_free(apriv);
    }
    else {
        printf("\n Usage mode: OpenSSLProj.exe fSrc.txt eSignFsrc.txt");
        return 1;
    }

    return 0;
}
