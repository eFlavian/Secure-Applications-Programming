#include <stdio.h>
#include <malloc.h>
#include <openssl/md5.h>

#define MESSAGE_CHUNK 200

int main(int argc, char** argv)
{
    // Check if the correct number of command-line arguments is provided
    if (argc == 2) {

        FILE* f = NULL;
        errno_t err;
        MD5_CTX ctx;

        // Array to store the final MD5 digest
        unsigned char finalDigest[MD5_DIGEST_LENGTH];

        // Initialize the MD5 context
        MD5_Init(&ctx); // Initialization of the MD5_CTX structure

        // Buffer to hold the content of the file
        unsigned char* fileBuffer = NULL;

        // Attempt to open the file in binary read mode
        err = fopen_s(&f, argv[1], "rb");
        if (err == 0) {
            // Move the file pointer to the end of the file to determine its length
            fseek(f, 0, SEEK_END);
            int fileLen = ftell(f);
            fseek(f, 0, SEEK_SET);

            // Allocate memory for a chunk of file content
            unsigned char* tmpBuffer_Chunk = (unsigned char*)malloc(MESSAGE_CHUNK);

            int read_length = MESSAGE_CHUNK;

            // Read the file content in chunks of MESSAGE_CHUNK bytes
            while (read_length == MESSAGE_CHUNK) {
                read_length = fread(tmpBuffer_Chunk, 1, MESSAGE_CHUNK, f);

                // Update the MD5 context with the current chunk of data
                MD5_Update(&ctx, tmpBuffer_Chunk, read_length);
            }

            // Finalize the MD5 digest, saving the A, B, C, D blocks in the right order into the message digest buffer
            MD5_Final(finalDigest, &ctx);

            // Display the computed MD5 digest in hexadecimal format
            printf("\nMD5 = ");
            for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
                printf("%02X ", finalDigest[i]);
                printf(" ");
            }

            printf("\n");

            // Close the file
            fclose(f);
        }

    } else {
        // Display usage information if the correct number of arguments is not provided
        printf("\n Usage Mode: ProgMainMD5.exe fSrc.txt \n\n");
        return 1;
    }

    return 0;
}
