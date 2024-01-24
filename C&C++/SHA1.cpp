#include <stdio.h>
#include <malloc.h>
#include <openssl/sha.h>

#define MESSAGE_CHUNK 256 

int main(int argc, char** argv)
{
    // Check if the correct number of command-line arguments is provided
    if (argc == 2) {

        FILE* f = NULL;
        errno_t err;
        SHA_CTX ctx;

        // Array to store the final SHA-1 digest
        unsigned char finalDigest[SHA_DIGEST_LENGTH];

        // Initialize the SHA-1 context
        SHA1_Init(&ctx);

        // Buffer to hold the content of the file
        unsigned char* fileBuffer = NULL;

        // Attempt to open the file in binary read mode
        err = fopen_s(&f, argv[1], "rb");
        if (err == 0) {
            // Move the file pointer to the end of the file to determine its length
            fseek(f, 0, SEEK_END);
            int fileLen = ftell(f);
            fseek(f, 0, SEEK_SET);

            // Allocate memory for the file content buffer
            fileBuffer = (unsigned char*)malloc(fileLen);

            // Read the entire file content into the buffer
            fread(fileBuffer, fileLen, 1, f);
            unsigned char* tmpBuffer = fileBuffer;

            // Process the file content in chunks of MESSAGE_CHUNK bytes
            while (fileLen > 0) {
                if (fileLen > MESSAGE_CHUNK) {
                    // Update the SHA-1 context with MESSAGE_CHUNK bytes of data
                    SHA1_Update(&ctx, tmpBuffer, MESSAGE_CHUNK);
                }
                else {
                    // Update the SHA-1 context with the remaining bytes of data
                    SHA1_Update(&ctx, tmpBuffer, fileLen);
                }
                fileLen -= MESSAGE_CHUNK;
                tmpBuffer += MESSAGE_CHUNK;
            }

            // Finalize the SHA-1 digest
            SHA1_Final(finalDigest, &ctx);

            // Display the computed SHA-1 digest in hexadecimal format
            printf("\nSHA1 = ");
            for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
                printf("%02X ", finalDigest[i]);
                printf(" ");
            }
            printf("\n\n");

            // Close the file
            fclose(f);
        }
    }
    else {
        // Display usage information if the correct number of arguments is not provided
        printf("\n Usage Mode: SHA1.exe fSrc.txt \n\n");
        return 1;
    }

    return 0;
}
