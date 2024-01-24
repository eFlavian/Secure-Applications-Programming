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
