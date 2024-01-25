# C / C++

## All the source code of the files is here:

```
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


#include <openssl/aes.h>
#include <stdio.h>

int main(int argc, char** argv)
{
    // Plaintext to be encrypted and decrypted
	unsigned char plaintext[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
								  0xab, 0xcd, 0xef, 0xff, 0xfe, 0xff, 0xdc, 0xba,
								  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
								  0x10, 0x01, 0x20, 0x22, 0x3a, 0x3b, 0xd4, 0xd5,
								  0xff };

    // Arrays to store the resulting ciphertext and restored plaintext
    unsigned char ciphertext[48];
    unsigned char restoringtext[48];

    // Initialization Vectors (IV) for encryption and decryption
	unsigned char IV_enc[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
						       0x01, 0x02, 0x03, 0x4, 0xff, 0xff, 0xff, 0xff };

	unsigned char IV_dec[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
						       0x01, 0x02, 0x03, 0x4, 0xff, 0xff, 0xff, 0xff };

    // Symmetric AES keys for 128, 192, and 256 bits
	unsigned char key_128[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
								0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0 };
	unsigned char key_192[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0,
								0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
								0x01, 0x02, 0x03, 0x04, 0x50, 0x51, 0x52, 0x53 };
	unsigned char key_256[] = { 0x01, 0x02, 0x03, 0x04, 0x50, 0x51, 0x52, 0x53,
								0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0,
								0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
								0x0f, 0x0f, 0x0f, 0x0f, 0xf0, 0xf0, 0xf0, 0xf0 };

    AES_KEY aes_key; // AES key structure

    // Set the encryption key for AES-256
    AES_set_encrypt_key(key_256, (sizeof(key_256) * 8), &aes_key);

    // Encryption using AES-CBC mode
    AES_cbc_encrypt(plaintext, ciphertext, sizeof(ciphertext), &aes_key, IV_enc, AES_ENCRYPT);

    // Display the ciphertext in hexadecimal format
    printf("Ciphertext for AES-CBC: ");
    for (unsigned int i = 0; i < sizeof(ciphertext); i++)
        printf("%02X", ciphertext[i]);
    printf("\n");

    // Set the decryption key for AES-256
    AES_set_decrypt_key(key_256, (sizeof(key_256) * 8), &aes_key);

    // Decryption using AES-CBC mode
    AES_cbc_encrypt(ciphertext, restoringtext, sizeof(restoringtext), &aes_key, IV_dec, AES_DECRYPT);

    // Display the restored plaintext in hexadecimal format
    printf("Restored plaintext for AES-CBC: ");
    for (unsigned int i = 0; i < sizeof(plaintext); i++)
        printf("%02X", restoringtext[i]);
    printf("\n");

    // Check if decryption was successful by comparing with the original plaintext
    unsigned flag = 1;
    for (unsigned int i = 0; i < sizeof(plaintext) && flag; i++) {
        if (plaintext[i] != restoringtext[i])
            flag = 0;
    }
    
    // Display the result of the decryption
    if (!flag)
        printf("Decryption failed!\n");
    else
        printf("Successful decryption!\n");

    return 0;
}


#include <openssl/aes.h>
#include <stdio.h>

int main(int argc, char** argv)
{
    // Plaintext to be encrypted and decrypted
    unsigned char plaintext[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xab, 0xcd, 0xef, 0xff, 0xfe, 0xff, 0xdc, 0xba,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x10, 0x01, 0x20, 0x22, 0x3a, 0x3b, 0xd4, 0xd5,
        0xff
    };

    // Arrays to store the resulting ciphertext and restored plaintext
    unsigned char ciphertext[48];
    unsigned char restoringtext[48];

    // Symmetric AES keys for 128, 192, and 256 bits
    unsigned char key_128[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0
    };
    unsigned char key_192[] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x01, 0x02, 0x03, 0x04, 0x50, 0x51, 0x52, 0x53
    };
    unsigned char key_256[] = {
        0x01, 0x02, 0x03, 0x04, 0x50, 0x51, 0x52, 0x53,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x0f, 0x0f, 0x0f, 0x0f, 0xf0, 0xf0, 0xf0, 0xf0
    };

    AES_KEY aes_key; // AES key structure

    // Set the encryption key for AES-192
    AES_set_encrypt_key(key_192, (sizeof(key_192) * 8), &aes_key);

    // Encryption using AES-ECB mode in 16-byte blocks
    for (unsigned int i = 0; i < sizeof(plaintext); i += 16)
        AES_encrypt(&plaintext[i], &ciphertext[i], &aes_key);

    // Display the ciphertext in hexadecimal format
    printf("Ciphertext for AES-ECB: ");
    for (unsigned int i = 0; i < sizeof(ciphertext); i++)
        printf("%02X", ciphertext[i]);
    printf("\n");

    // Set the decryption key for AES-192
    AES_set_decrypt_key(key_192, (sizeof(key_192) * 8), &aes_key);

    // Decryption using AES-ECB mode in 16-byte blocks
    for (unsigned int i = 0; i < sizeof(ciphertext); i += 16)
        AES_decrypt(&ciphertext[i], &restoringtext[i], &aes_key);

    // Display the restored plaintext in hexadecimal format
    printf("Restored plaintext for AES-ECB: ");
    for (unsigned int i = 0; i < sizeof(plaintext); i++)
        printf("%02X", restoringtext[i]);
    printf("\n");

    // Check if decryption was successful by comparing with the original plaintext
    unsigned flag = 1;
    for (unsigned int i = 0; i < sizeof(plaintext) && flag; i++) {
        if (plaintext[i] != restoringtext[i])
            flag = 0;
    }

    // Display the result of the decryption
    if (!flag)
        printf("Decryption failed!\n");
    else
        printf("Successful decryption!\n");

    return 0;
}


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


#include <stdio.h>
#include <malloc.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>

int main()
{
    RSA* rsaKP = NULL;

    // Generate RSA key pair with 1024 bits, public exponent 65535 (standard value), and no callback and no user data
    rsaKP = RSA_generate_key(1024, 65535, NULL, NULL);

    // Check the validity of the generated key pair
    RSA_check_key(rsaKP);

    // File pointer for the private key file
    FILE* fpPriv = NULL;
    // Create or open the file to store the RSA private key in PEM format
    fopen_s(&fpPriv, "privKeyReceiver.pem", "w+");
    
    // Write the RSA private key to the file in PEM format
    PEM_write_RSAPrivateKey(fpPriv, rsaKP, NULL, NULL, 0, 0, NULL);
    
    // Close the file
    fclose(fpPriv);

    // File pointer for the public key file
    FILE* fpPub = NULL;
    // Create or open the file to store the RSA public key in PEM format
    fopen_s(&fpPub, "pubKeyReceiver.pem", "w+");
    
    // Write the RSA public key to the file in PEM format
    PEM_write_RSAPublicKey(fpPub, rsaKP);
    
    // Close the file
    fclose(fpPub);

    // Free the allocated storage for RSA key pair
    RSA_free(rsaKP);

    // Print a message indicating the completion of the RSA key pair generation
    printf("\n The RSA key pair generated! \n");

    return 0;
}


#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <openssl/applink.c>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

int main()
{
    // Create a new X.509 certificate
    X509* X509Cert = X509_new();

    // Set the version of the X.509 certificate (v3)
    X509_set_version(X509Cert, 0x2);

    // Set the serial number of the certificate
    ASN1_INTEGER_set(X509_get_serialNumber(X509Cert), 1);

    // Set issuer information
    X509_NAME_add_entry_by_txt(X509_get_issuer_name(X509Cert), "C", MBSTRING_ASC, (unsigned char*)"RO", -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_issuer_name(X509Cert), "O", MBSTRING_ASC, (unsigned char*)"ASE", -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_issuer_name(X509Cert), "OU", MBSTRING_ASC, (unsigned char*)"ITC Security Master", -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_issuer_name(X509Cert), "CN", MBSTRING_ASC, (unsigned char*)"Marius Popa", -1, -1, 0);

    // Set subject information (same as issuer for simplicity)
    X509_NAME_add_entry_by_txt(X509_get_subject_name(X509Cert), "C", MBSTRING_ASC, (unsigned char*)"RO", -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(X509Cert), "O", MBSTRING_ASC, (unsigned char*)"ASE", -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(X509Cert), "OU", MBSTRING_ASC, (unsigned char*)"ITC Security Master", -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(X509Cert), "CN", MBSTRING_ASC, (unsigned char*)"Marius Popa", -1, -1, 0);

    // Set the validity period of the certificate
    int DaysStart = 1;
    int DaysStop = 7;
    X509_gmtime_adj(X509_get_notBefore(X509Cert), (long)60 * 60 * 24 * DaysStart);
    X509_gmtime_adj(X509_get_notAfter(X509Cert), (long)60 * 60 * 24 * DaysStop);

    // Create a new EVP_PKEY structure and associate it with an RSA key pair
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(1024, 65535, NULL, NULL);
    EVP_PKEY_set1_RSA(pkey, rsa);

    // Set the public key of the certificate
    X509_set_pubkey(X509Cert, pkey);

    // Set the digest algorithm (SHA-1 in this case)
    const EVP_MD* dgAlg = EVP_sha1();

    // Sign the certificate with the private key
    X509_sign(X509Cert, pkey, dgAlg);

    // Write the certificate to a file ("SampleCert.cer")
    BIO* out1 = BIO_new_file("SampleCert.cer", "w");
    i2d_X509_bio(out1, X509Cert);
    BIO_free(out1);

    // Write the private key to a file ("privateKeyCert.key")
    BIO* out2 = BIO_new_file("privateKeyCert.key", "w");
    i2d_PrivateKey_bio(out2, pkey);
    BIO_free(out2);

    // Free allocated resources
    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    X509_free(X509Cert);

    return 0;
}


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


#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <stdio.h>

// https://github.com/richmit/ex-OpenSSL/blob/master/evp_encrypt.c

#define INBUFSIZE 512
#define OUTBUFSIZE (512*512)

void prtErrAndExit(int eVal, char* msg);
int main(int argc, char* argv[]);

int main(int argc, char* argv[]) {
    // Variables for handling encryption
    int outBytes, inBytes, tmpOutBytes, bytesInBuf, i;
    int cipherBlockSize, cipherKeyLength, cipherIvLength;
    unsigned char key[] = { /* Need all 32 bytes... */ /* Key for AES-256 encryption */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    unsigned char iv[] = { /* Only need 16 bytes... */ /* Initialization Vector for AES-256-CBC mode */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    unsigned char buf2crypt[INBUFSIZE];
    unsigned char outBuf[OUTBUFSIZE];
    EVP_CIPHER_CTX *ctx;

    // Initialize the OpenSSL library
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx); // Allocation/initilization of the cipher context structure
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv); // Specifies the actual cipher to be used in the implementation below

    // Get cipher parameters
    cipherBlockSize = EVP_CIPHER_CTX_block_size(ctx);
    cipherKeyLength = EVP_CIPHER_CTX_key_length(ctx); // Validate against the key input
    cipherIvLength = EVP_CIPHER_CTX_iv_length(ctx);   // Validate against the iv input

    // Print information about encryption parameters
    fprintf(stderr, "INFO(evp_encrypt): Enc Algo:   %s\n", OBJ_nid2ln(EVP_CIPHER_CTX_nid(ctx)));
    fprintf(stderr, "INFO(evp_encrypt): Key:        ");
    for (i = 0; i < cipherKeyLength; i++)
        fprintf(stderr, "%02X", (int)(key[i]));
    fprintf(stderr, "\n");
    fprintf(stderr, "INFO(evp_encrypt): IV:         ");
    for (i = 0; i < cipherIvLength; i++)
        fprintf(stderr, "%02X", (int)(iv[i]));
    fprintf(stderr, "\n");
    fprintf(stderr, "INFO(evp_encrypt): block size: %d\n", cipherBlockSize);
    fprintf(stderr, "INFO(evp_encrypt): key length: %d\n", cipherKeyLength);
    fprintf(stderr, "INFO(evp_encrypt): IV length:  %d\n", cipherIvLength);

    // Check key and IV lengths
    if ((cipherKeyLength > 32) || (cipherIvLength > 16))
        prtErrAndExit(1, (char*)"ERROR: Hardwired key or iv was too short!!\n");

    fprintf(stderr, "INFO(evp_encrypt): READING DATA -----> ");
    inBytes = outBytes = 0;

    //strcpy((char*)buf2crypt, "qwerty"); // Uncomment if you want to use a predefined string for testing
    //bytesInBuf = strlen((const char*)buf2crypt);

    // Read input data from stdin in chunks of INBUFSIZE bytes
    while ((bytesInBuf = fread(buf2crypt, sizeof(char), INBUFSIZE, stdin)) > 0) {
        fprintf(stderr, ".");
        // Check if the buffer is big enough to hold the encrypted data
        if ((OUTBUFSIZE - ((bytesInBuf + cipherBlockSize - 1) + outBytes)) <= 0)
            prtErrAndExit(1, (char*)"ERROR: Buffer was not big enough to hold encrypted data!!\n");

        // Apply encryption on buf2crypt; encrypted content added to outBuf + outBytes
        // Note: Subtracting 1 from bytesInBuf to avoid processing the newline character when encrypting text
        if (!EVP_EncryptUpdate(ctx, outBuf + outBytes, &tmpOutBytes, buf2crypt, bytesInBuf - 1))
            prtErrAndExit(1, (char*)"ERROR: EVP_EncryptUpdate didn't work...\n");

        outBytes += tmpOutBytes;
        //inBytes += bytesInBuf ;
        inBytes += bytesInBuf - 1;
    } /* end while */
    fprintf(stderr, "DONE\n");

    // Check if the buffer is big enough for the final encrypted data
    if ((OUTBUFSIZE - (cipherBlockSize + outBytes)) <= 0)
        prtErrAndExit(1, (char*)"ERROR: Buffer was not big enough to hold encrypted data!!\n");

    // Perform final operations over the buffers to conclude the encryption
    if (!EVP_EncryptFinal_ex(ctx, outBuf + outBytes, &tmpOutBytes))
        prtErrAndExit(1, (char*)"ERROR: EVP_EncryptFinal_ex didn't work...\n");

    outBytes += tmpOutBytes;

    // Print information about the encryption process
    fprintf(stderr, "INFO(evp_encrypt): Bytes in:   %d\n", inBytes);
    fprintf(stderr, "INFO(evp_encrypt): Bytes out:  %d\n", outBytes);

    // Release/deallocate internals for the cipher context ctx
    EVP_CIPHER_CTX_cleanup(ctx);

    // Write the encrypted data to stdout
    fwrite(outBuf, 1, outBytes, stdout);

    fprintf(stdout, "\n Encrypted: ");
    for (int i = 0; i < outBytes; i++)
        fprintf(stdout, "%02X ", outBuf[i]);

    // Write the encrypted data to binary and text files
    FILE* fb, * ft;
    fb = fopen("str_bin.enc", "wb+"); // Binary file with encrypted content
    ft = fopen("str_txt.enc", "w+"); // Text file with hexadecimal representation of encrypted content (ASCII)

    fwrite(outBuf, 1, outBytes, fb); // Copy all content of outBuf into str_bin.enc

    fprintf(ft, "%d\n", inBytes);
    for (int i = 0; i < outBytes; i++)
        fprintf(ft, "%02X", outBuf[i]);

    fclose(fb);
    fclose(ft);

    return 1;
} /* end func main */

// Save some vertical space with this simple error handling function
void prtErrAndExit(int eVal, char* msg) {
    if (msg != NULL)
        fprintf(stderr, "INFO(evp_encrypt): %s\n\n", msg);
    exit(eVal);
} /* end func prtErrAndExit */


#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define INBUFSIZE 512
#define OUTBUFSIZE (512*512)

void prtErrAndExit(int eVal, char* msg);
int main(int argc, char* argv[]);

int main(int argc, char* argv[]) {
    // Variables for handling encryption
    int outBytes, tmpOutBytes, bytesInBuf, i;
    int cipherBlockSize, cipherKeyLength, cipherIvLength;
    unsigned char key[] = { /* Need all 32 bytes... */ /* Key for AES-256 encryption */
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    unsigned char iv[] = { /* Only need 16 bytes... */ /* Initialization Vector for AES-256-CBC mode */
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    unsigned char buf2crypt[INBUFSIZE];
    unsigned char outBuf[OUTBUFSIZE];
    EVP_CIPHER_CTX *ctx;

    // Initialize the OpenSSL library
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    // Get cipher parameters
    cipherBlockSize = EVP_CIPHER_CTX_block_size(ctx);
    cipherKeyLength = EVP_CIPHER_CTX_key_length(ctx);
    cipherIvLength = EVP_CIPHER_CTX_iv_length(ctx);

    // Print information about encryption parameters
    fprintf(stderr, "INFO(evp_decrypt): Enc Algo:   %s\n", OBJ_nid2ln(EVP_CIPHER_CTX_nid(ctx)));
    fprintf(stderr, "INFO(evp_decrypt): Key:        ");
    for (i = 0; i < cipherKeyLength; i++)
        fprintf(stderr, "%02X", (int)(key[i]));
    fprintf(stderr, "\n");
    fprintf(stderr, "INFO(evp_decrypt): IV:         ");
    for (i = 0; i < cipherIvLength; i++)
        fprintf(stderr, "%02X", (int)(iv[i]));
    fprintf(stderr, "\n");
    fprintf(stderr, "INFO(evp_decrypt): block size: %d\n", cipherBlockSize);
    fprintf(stderr, "INFO(evp_decrypt): key length: %d\n", cipherKeyLength);
    fprintf(stderr, "INFO(evp_decrypt): IV length:  %d\n", cipherIvLength);

    // Check key and IV lengths
    if ((cipherKeyLength > 32) || (cipherIvLength > 16))
        prtErrAndExit(1, (char*)"ERROR: Hardwired key or iv was too short!!\n");

    // Decrypt text file
    FILE* ft;
    ft = fopen("str_txt.enc", "r");

    // Read length of the original plaintext and ciphertext
    unsigned int plaintext_length;
    fscanf(ft, "%u\n", &plaintext_length);
    unsigned char infile_buffer[INBUFSIZE];
    fscanf(ft, "%s", infile_buffer);

    // Convert hexadecimal string to bytes
    unsigned char* ptr, pair[2];
    ptr = infile_buffer;
    for (unsigned char i = 0; i < strlen((const char*)infile_buffer); i += 2)
    {
        memcpy(pair, ptr, 2); // each hex pair has 2 bytes
        buf2crypt[i / 2] = (unsigned char)strtol((const char*)pair, NULL, 16);
        ptr += 2; // each hex pair has 2 bytes
    }
    bytesInBuf = strlen((const char*)infile_buffer) / 2; // each hex pair has 2 bytes
    outBytes = 0; // offset of the 1st byte within outBuf containing the restored plaintext

    // Decrypt the ciphertext
    if (!EVP_DecryptUpdate(ctx, outBuf + outBytes, &tmpOutBytes, buf2crypt, bytesInBuf))
        prtErrAndExit(1, (char*)"ERROR: EVP_DecryptUpdate didn't work...\n");
    outBytes += tmpOutBytes;

    // Check if the buffer is big enough
    if ((OUTBUFSIZE - (cipherBlockSize + outBytes)) <= 0)
        prtErrAndExit(1, (char*)"ERROR: Buffer was not big enough to hold decrypted data!!\n");

    // Finalize the decryption
    if (!EVP_DecryptFinal_ex(ctx, outBuf + outBytes, &tmpOutBytes))
        prtErrAndExit(1, (char*)"ERROR: EVP_DecryptFinal_ex didn't work...\n");
    outBytes += tmpOutBytes;

    // Print information about the decryption process
    fprintf(stderr, "\n\nINFO(evp_decrypt): Bytes in (text file):   %d\n", bytesInBuf);
    fprintf(stderr, "INFO(evp_decrypt): Bytes out (text file):  %d\n", plaintext_length);

    // Print the restored plaintext
    outBuf[plaintext_length] = 0; // put the string terminator right after the last byte of the initial plaintext
    fprintf(stderr, "\nRestored plaintext from the encrypted text file ---> %s\n", outBuf);

    // Close the text file
    fclose(ft);

    // Decrypt binary file
    FILE* fb;
    fb = fopen("str_bin.enc", "rb");

    // Reset the context for binary decryption
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    // Get cipher parameters for binary decryption
    cipherBlockSize = EVP_CIPHER_CTX_block_size(ctx);
    cipherKeyLength = EVP_CIPHER_CTX_key_length(ctx);
    cipherIvLength = EVP_CIPHER_CTX_iv_length(ctx);

    // Check key and IV lengths for binary decryption
    if ((cipherKeyLength > 32) || (cipherIvLength > 16))
        prtErrAndExit(1, (char*)"ERROR: Hardwired key or iv was too short!!\n");

    // Get the length of the binary ciphertext
    unsigned int infile_length;
    fseek(fb, 0, SEEK_END);
    infile_length = ftell(fb);
    fseek(fb, 0, SEEK_SET);

    // Read the binary ciphertext
    fread(buf2crypt, infile_length, 1, fb);

    outBytes = 0; // offset of the 1st byte within outBuf containing the restored plaintext

    // Decrypt the binary ciphertext
    if (!EVP_DecryptUpdate(ctx, outBuf + outBytes, &tmpOutBytes, buf2crypt, infile_length))
        prtErrAndExit(1, (char*)"ERROR: EVP_DecryptUpdate didn't work...\n");
    outBytes += tmpOutBytes;

    // Check if the buffer is big enough for binary decryption
    if ((OUTBUFSIZE - (cipherBlockSize + outBytes)) <= 0)
        prtErrAndExit(1, (char*)"ERROR: Buffer was not big enough to hold decrypted data!!\n");

    // Finalize the binary decryption
    if (!EVP_DecryptFinal_ex(ctx, outBuf + outBytes, &tmpOutBytes))
        prtErrAndExit(1, (char*)"ERROR: EVP_DecryptFinal_ex didn't work...\n");
    outBytes += tmpOutBytes;

    // Print information about the binary decryption process
    fprintf(stderr, "INFO(evp_decrypt): Bytes in (binary file):   %d\n", infile_length);
    fprintf(stderr, "INFO(evp_decrypt): Bytes out (binary file):  %d\n", plaintext_length);

    // Cleanup the context after binary decryption
    EVP_CIPHER_CTX_cleanup(ctx);

    // Print the restored plaintext from the binary file
    outBuf[plaintext_length] = 0; // put the string terminator right after the last byte of the initial plaintext
    fprintf(stderr, "\nRestored plaintext from the encrypted binary file ---> %s\n", outBuf);

    // Close the binary file
    fclose(fb);

    return 1;
} /* end func main */

/* Save some vertical space with this simple error handling function.. */
void prtErrAndExit(int eVal, char* msg) {
    if (msg != NULL)
        fprintf(stderr, "INFO(evp_decrypt): %s\n\n", msg);
    exit(eVal);
} /* end func prtErrAndExit */


#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>

int main(int argc, char** argv)
{
    if (argc == 4) {
        FILE* fsrc = NULL;
        FILE* fdst = NULL;
        FILE* frst = NULL;
        errno_t err;

        // Open the source file for reading in binary mode
        err = fopen_s(&fsrc, argv[1], "rb");
        fseek(fsrc, 0, SEEK_END);
        int fileLen = ftell(fsrc);
        fseek(fsrc, 0, SEEK_SET);

        RSA* apub;
        RSA* apriv;
        FILE* f;

        unsigned char* e_data = NULL;
        unsigned char* last_data = NULL;

        // RSA encryption
        f = fopen("pubKeyReceiver.pem", "r");
        apub = PEM_read_RSAPublicKey(f, NULL, NULL, NULL); // Load RSA public key components into RSA structure
        fclose(f);

        err = fopen_s(&fdst, argv[2], "wb");

        // Allocate buffers for data
        unsigned char* fsrcbuf = (unsigned char*)malloc(RSA_size(apub) + 1); // Buffer to store plaintext chunks, each chunk has 128 bytes (RSA key length)
        fsrcbuf[RSA_size(apub)] = 0x00;
        e_data = (unsigned char*)malloc(RSA_size(apub)); // Buffer to store the ciphertext with the same size as the RSA key length

        if (fileLen != RSA_size(apub)) {
            while (fread_s(fsrcbuf, RSA_size(apub), sizeof(unsigned char), RSA_size(apub), fsrc) == RSA_size(apub)) {
                // Encryption block-by-block; each block has RSA key length (1024 bits)
                // Because the block is filled fully, no padding is used here
                RSA_public_encrypt(RSA_size(apub), fsrcbuf, e_data, apub, RSA_NO_PADDING);
                fwrite(e_data, sizeof(unsigned char), RSA_size(apub), fdst);
            }
        }
        else {
            fread_s(fsrcbuf, RSA_size(apub), sizeof(unsigned char), RSA_size(apub), fsrc);
        }

        if (fileLen % RSA_size(apub)) // If there are additional bytes to be encrypted
        {
            // Encryption of the last block with padding because it could be a partial block (less than 1024 bits)
            RSA_public_encrypt(fileLen % RSA_size(apub), fsrcbuf, e_data, apub, RSA_PKCS1_PADDING);
            fwrite(e_data, sizeof(unsigned char), RSA_size(apub), fdst);
        }

        // RSA decryption
        f = fopen("privKeyReceiver.pem", "r");
        apriv = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL); // Load RSA private key components into RSA structure
        fclose(f);

        free(e_data);
        e_data = (unsigned char*)malloc(RSA_size(apub)); // Buffer to store the input ciphertext block with 128 bytes 
        last_data = (unsigned char*)malloc(RSA_size(apub)); // Buffer to store the restored block of the plaintext
        fclose(fdst);

        fopen_s(&fdst, argv[2], "rb");
        fseek(fdst, 0, SEEK_END);
        int fileLen2 = ftell(fdst);
        fseek(fdst, 0, SEEK_SET);

        int maxChunks = fileLen2 / RSA_size(apub); // Number of ciphertext blocks
        int currentChunk = 1;

        err = fopen_s(&frst, argv[3], "wb");

        if (fileLen2 != RSA_size(apub)) {
            while (fread_s(e_data, RSA_size(apub), sizeof(unsigned char), RSA_size(apub), fdst) == RSA_size(apub)) {
                if (currentChunk != maxChunks) { // 1 to (maxChunks - 1) are considered here because no padding
                    // Decryption done block-by-block; each block must have 1024 bits as length
                    // Because each block is filled fully, no padding is added here
                    RSA_private_decrypt(RSA_size(apub), e_data, last_data, apriv, RSA_NO_PADDING);
                    fwrite(last_data, sizeof(unsigned char), RSA_size(apub), frst);
                    currentChunk++;
                }
            }
        }
        else {
            fread_s(e_data, RSA_size(apub), sizeof(unsigned char), RSA_size(apub), fdst);
        }

        if (fileLen % RSA_size(apub)) {
            // Could be a partial block; the padding must be used to meet the length of RSA key
            RSA_private_decrypt(fileLen % RSA_size(apub), e_data, last_data, apriv, RSA_PKCS1_PADDING);
            fwrite(last_data, sizeof(unsigned char), fileLen % RSA_size(apub), frst);
        }
        else {
            // The last block to be decrypted is a full block in plaintext; no padding required for decryption
            RSA_private_decrypt(RSA_size(apub), e_data, last_data, apriv, RSA_NO_PADDING);
            fwrite(last_data, sizeof(unsigned char), RSA_size(apub), frst);
        }

        free(last_data);
        free(e_data);
        free(fsrcbuf);

        RSA_free(apub);
        RSA_free(apriv);

        fseek(frst, 0, SEEK_END);
        printf("Nr. of bytes on the decrypted file: %d \n", ftell(frst));
        fseek(fsrc, 0, SEEK_END);
        printf("Nr. of bytes on the input file: %d", ftell(fsrc));

        fclose(fsrc);
        fclose(frst);
        fclose(fdst);
    }
    else {
        printf("\n Usage mode: OpenSSLProj.exe f1.txt encryptf1.txt f9.txt");
        return 1;
    }

    return 0;
}

```