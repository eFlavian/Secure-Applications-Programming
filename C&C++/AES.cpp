#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <openssl/aes.h>

int main(int argc, char** argv)
{
    // Check if the correct number of command-line arguments is provided
    if (argc == 5) {
        FILE* fSrc = NULL, * fDst = NULL;

        char opt[3];
        char mode[7];
        strcpy(opt, argv[1]);  // Copy the encryption/decryption option from command-line argument
        strcpy(mode, argv[2]); // Copy the encryption mode from command-line argument

        AES_KEY akey; // AES key structure
        unsigned char* inBuf = NULL;
        unsigned char* outBuf;
        unsigned char ivec[16];
        unsigned char userSymmetricKey[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                               0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
        unsigned char wrongSymmetricKey[16] = { 0x11, 0x11, 0xf2, 0xf3, 0xc4, 0x55, 0xa6, 0xa7,
                                                0xa0, 0xa1, 0x92, 0x93, 0x94, 0x95, 0x56, 0x77 };

        // Encryption
        if (strcmp(opt, "-e") == 0) {
            fopen_s(&fSrc, argv[3], "rb"); // Open source file for reading in binary mode
            fopen_s(&fDst, argv[4], "wb"); // Open destination file for writing in binary mode
            fseek(fSrc, 0, SEEK_END);
            long int inLen = ftell(fSrc); // Get file size in bytes
            fseek(fSrc, 0, SEEK_SET);
            long int outLen = 0;
            
            // Calculate the total size of the ciphertext after encryption
            if ((inLen % 16) == 0)
                outLen = inLen;
            else
                outLen = ((inLen / 16) * 16) + 16;

            // Allocate memory for input and output buffers
            inBuf = (unsigned char*)malloc(outLen);
            outBuf = (unsigned char*)malloc(outLen);
            memset(inBuf, 0x00, outLen);
            
            // Copy the file content into inBuf
            fread(inBuf, inLen, 1, fSrc);

            // Set AES key for encryption (128 bits)
            AES_set_encrypt_key(userSymmetricKey, 128, &akey);

            if (strcmp(mode, "-ecb") == 0) {
                // AES-ECB encryption done block-by-block (AES block is 16 bytes)
                for (int i = 0; i < (outLen / 16); i++)
                    AES_encrypt(&(inBuf[i * 16]), &(outBuf[i * 16]), &akey);
            }
            else {
                // Set the content of the initialization vector (IV)
                memset(&ivec, 0x01, sizeof(ivec));
                // AES-CBC encryption done in one single step for the entire plaintext as input
                AES_cbc_encrypt(inBuf, outBuf, outLen, &akey, ivec, AES_ENCRYPT);
            }

            // Save the size of the plaintext into the encrypted file
            fwrite(&inLen, sizeof(inLen), 1, fDst);
            // Save the ciphertext into the file
            fwrite(outBuf, outLen, 1, fDst);
            
            // Free allocated memory and close files
            free(outBuf);
            free(inBuf);
            fclose(fDst);
            fclose(fSrc);
        }
        // Decryption
        else {
            fopen_s(&fSrc, argv[3], "rb"); // Open source file for reading in binary mode
            fopen_s(&fDst, argv[4], "wb"); // Open destination file for writing in binary mode
            fseek(fSrc, 0, SEEK_END);
            long int inLen = ftell(fSrc) - 4; // inLen - ciphertext length
            fseek(fSrc, 0, SEEK_SET);
            long int outLen = 0;
            
            // Read the size of the restored message from the first 4 bytes of the ciphertext file
            fread(&outLen, sizeof(outLen), 1, fSrc);

            // Allocate memory for input and output buffers
            inBuf = (unsigned char*)malloc(inLen);
            outBuf = (unsigned char*)malloc(inLen);
            memset(inBuf, 0x00, inLen);
            
            // Read the ciphertext content
            fread(inBuf, inLen, 1, fSrc);

            // Set the AES key for decryption; must be the same as the one used for encryption
            AES_set_decrypt_key(userSymmetricKey, 128, &akey);

            if (strcmp(mode, "-ecb") == 0) {
                // AES-ECB decryption block-by-block
                for (int i = 0; i < (inLen / 16); i++)
                    AES_decrypt(&(inBuf[i * 16]), &(outBuf[i * 16]), &akey);
            }
            else {
                // Set the content of the initialization vector (IV)
                memset(&ivec, 0x02, sizeof(ivec));
                // AES-CBC decryption as a one-shot operation
                AES_cbc_encrypt(inBuf, outBuf, inLen, &akey, ivec, AES_DECRYPT);
            }

            // Save the restored message into a file
            fwrite(outBuf, outLen, 1, fDst);
            
            // Free allocated memory and close files
            free(outBuf);
            free(inBuf);
            fclose(fDst);
            fclose(fSrc);
        }
    }
    else {
        // Display usage information if the correct number of command-line arguments is not provided
        printf("\n Usage Mode: OpenSSLProj.exe -e -cbc fSrc.txt fDst.txt");
        printf("\n Usage Mode: OpenSSLProj.exe -d -ecb fSrc.txt fDst.txt");
        return 1;
    }

    // Display a message indicating the completion of the process
    printf("\n Process done.");

    return 0;
}
