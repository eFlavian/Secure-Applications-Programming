#include <iostream>
#include <cstdio>
#include <string>
#include <openssl/aes.h>
#include <openssl/rand.h>

using namespace std;

int main()
{
    // read from file in C
    FILE* file;
    long fileSize;
    unsigned char* buffer; // atentie sizeof(buffer) este 4 pt ca un pointer = 4 bytes

    // Open the file for binary reading using fopen_s
    if (fopen_s(&file, "response.txt", "rb") != 0) {
        perror("Error opening the file");
        return 1; // Return an error code
    }

    // Determine the file size
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the byte array
    buffer = (unsigned char*)malloc(fileSize);
    if (buffer == NULL) {
        perror("Error allocating memory");
        fclose(file);
        return 1; // Return an error code
    }

    fread(buffer, 1, fileSize, file); // buffer gets content of response.txt

    // Close the file
    fclose(file);

    // Random AES 128 bit key.
    unsigned char key128[16]; // 128 bits = 16 bytes

    if (RAND_bytes(key128, sizeof(key128)) != 1) {
        // Handle error: the random number generator failed
        fprintf(stderr, "Error generating random bytes.\n");
        return 1;
    }

    printf("\nGenerated AES 128-bit key:\n");
    for (int i = 0; i < sizeof(key128); i++) {
        printf("%02x", key128[i]);
    }

    unsigned char ciphertext[48];

    printf("\n");

    AES_KEY aes_key; // AES key structure

    // Set the encryption key for AES-128
    AES_set_encrypt_key(key128, (sizeof(key128) * 8), &aes_key);

    // Encryption using AES-ECB mode in 16-byte blocks
    for (unsigned int i = 0; i < sizeof(buffer); i += 16)
        AES_encrypt(&buffer[i], &ciphertext[i], &aes_key);

    // ciphertext contains the content of response.txt

    // Display the ciphertext in hexadecimal format
    printf("\nCiphertext for response.txt in AES-ECB: ");
    for (unsigned int i = 0; i < sizeof(ciphertext); i++)
        printf(" %02X", ciphertext[i]);
    printf("\n");


    unsigned char restoringtext[48];

    // Set the decryption key for AES-192
    AES_set_decrypt_key(key128, (sizeof(key128) * 8), &aes_key);

    // Decryption using AES-ECB mode in 16-byte blocks
    for (unsigned int i = 0; i < sizeof(ciphertext); i += 16)
        AES_decrypt(&ciphertext[i], &restoringtext[i], &aes_key);

    // Display the restored plaintext in hexadecimal format
    printf("Restored plaintext for AES-ECB: ");
    for (unsigned int i = 0; i < fileSize; i++)
        printf("%c", restoringtext[i]);
    printf("\n");

    // Free allocated memory
    free(buffer);

    return 0;
}
