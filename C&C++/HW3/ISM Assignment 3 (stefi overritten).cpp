#include <openssl/aes.h>
#include <stdio.h>
#include <string>
#include <cstring> 
using namespace std;

class AESCipher {
private:
    string algorithm;

public:
    static const string DECRYPTION;
    static const string ENCRYPTION;
    static const string AES_CBC_ALGORITHM;
    static const string AES_ECB_ALGORITHM;

    AESCipher(string algorithm) {
        this->algorithm = algorithm;
    }

    unsigned char* encrypt(const unsigned char input[], size_t input_len) {
        unsigned char ciphertext[48] = {};
        unsigned char IV[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                               0x01, 0x02, 0x03, 0x4, 0xff, 0xff, 0xff, 0xff };
        if (this->algorithm == AESCipher::AES_CBC_ALGORITHM) {
            unsigned char key_256[] = { 0x01, 0x02, 0x03, 0x04, 0x50, 0x51, 0x52, 0x53,
                                        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0,
                                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                        0x0f, 0x0f, 0x0f, 0x0f, 0xf0, 0xf0, 0xf0, 0xf0 };
            AES_KEY aes_key;

            AES_set_encrypt_key(key_256, (sizeof(key_256) * 8), &aes_key);

            AES_cbc_encrypt(input, ciphertext, input_len, &aes_key, IV, AES_ENCRYPT);
        }
        else if (this->algorithm == AESCipher::AES_ECB_ALGORITHM) {
            unsigned char key_128[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0 };
            AES_KEY aes_key;
            AES_set_encrypt_key(key_128, 128, &aes_key);

            for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE) {
                AES_ecb_encrypt(input + i, ciphertext + i, &aes_key, AES_ENCRYPT);
            }
        }
        return ciphertext;
    }

    unsigned char* decrypt(const unsigned char* ciphertext, size_t ciphertext_len) {
        unsigned char restoringtext[48] = {};
        unsigned char IV[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                               0x01, 0x02, 0x03, 0x4, 0xff, 0xff, 0xff, 0xff };
        if (this->algorithm == AESCipher::AES_CBC_ALGORITHM) {
            unsigned char key_256[] = { 0x01, 0x02, 0x03, 0x04, 0x50, 0x51, 0x52, 0x53,
                                        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0,
                                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                        0x0f, 0x0f, 0x0f, 0x0f, 0xf0, 0xf0, 0xf0, 0xf0 };
            AES_KEY aes_key;

            AES_set_decrypt_key(key_256, (sizeof(key_256) * 8), &aes_key);

            AES_cbc_encrypt(ciphertext, restoringtext, ciphertext_len, &aes_key, IV, AES_DECRYPT);

            printf("\nRestored plaintext for AES-CBC: ");
            for (size_t i = 0; i < ciphertext_len; i++)
                printf("%02X", restoringtext[i]);
        }
        else if (this->algorithm == AESCipher::AES_ECB_ALGORITHM) {
            unsigned char key_128[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0 };
            AES_KEY aes_key;
            AES_set_decrypt_key(key_128, (sizeof(key_128) * 8), &aes_key);

            for (unsigned int i = 0; i < sizeof(ciphertext); i += 16)
                AES_set_decrypt_key(key_128, 128, &aes_key);

            for (size_t i = 0; i < ciphertext_len; i += AES_BLOCK_SIZE) {
                AES_ecb_encrypt(ciphertext + i, restoringtext + i, &aes_key, AES_DECRYPT);
            }
            printf("\nRestored plaintext for AES-ECB: ");
            for (size_t i = 0; i < ciphertext_len; i++)
                printf("%02X", restoringtext[i]);
        }
        return restoringtext;
    }
};

const string AESCipher::AES_CBC_ALGORITHM = "CBC";
const string AESCipher::AES_ECB_ALGORITHM = "ECB";
const string AESCipher::DECRYPTION = "Decryption";
const string AESCipher::ENCRYPTION = "Encryption";

int main(int argc, char** argv) {
    unsigned char plaintext[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xab, 0xcd, 0xef, 0xff, 0xfe, 0xff, 0xdc, 0xba,
                                  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                  0x10, 0x01, 0x20, 0x22, 0x3a, 0x3b, 0xd4, 0xd5,
                                  0xff };
    AESCipher AEC_CBC(AESCipher::AES_CBC_ALGORITHM);
    size_t input_len = sizeof(plaintext);
    unsigned char* result_enc_cbc = AEC_CBC.encrypt(plaintext, input_len);
    printf("\nCiphertext for AES-CBC: ");
    for (size_t i = 0; i < input_len; ++i) {
        printf("%02X ", result_enc_cbc[i]);
    }
    unsigned char* result_dec_cbc = AEC_CBC.decrypt(result_enc_cbc, input_len);

    AESCipher AEC_ECB(AESCipher::AES_ECB_ALGORITHM);
    unsigned char* result_enc_ecb = AEC_ECB.encrypt(plaintext, input_len);
    printf("\nCiphertext for AES-ECB: ");
    for (size_t i = 0; i < input_len; ++i) {
        printf("%02X ", result_enc_ecb[i]);
    }
    unsigned char* result_dec_ecb = AEC_ECB.decrypt(result_enc_ecb, input_len);

    return 0;
}
