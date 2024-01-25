#include <iostream>
#include <openssl/aes.h>

using namespace std;

class AESCipher {
public:
    //AES algorithms
    enum AESAlgorithm { AES_ECB, AES_CBC };

    // ECB Constructor 
    AESCipher(AESAlgorithm algorithm, unsigned char* key) {
        this->algorithm = algorithm;
        AES_set_encrypt_key(key, 128, &this->encryptKey);  // Assuming 128-bit key for simplicity
        AES_set_decrypt_key(key, 128, &this->decryptKey);
    }

    // CBC Constructor
    AESCipher(AESAlgorithm algorithm, unsigned char* key, unsigned char* iv) : AESCipher(algorithm, key) {
        memcpy(this->iv, iv, AES_BLOCK_SIZE);
    }

    // Encrypts the plaintext
    string encrypt(const unsigned char* plaintext, int length) {
        int c_len = length + AES_BLOCK_SIZE - (length % AES_BLOCK_SIZE); // Adjusted length
        unsigned char* modifiablePlaintext = new unsigned char[c_len];   // Use adjusted length
        memcpy(modifiablePlaintext, plaintext, length); // Copy original plaintext

        memset(modifiablePlaintext + length, 0, c_len - length);

        // Choose what algorithm to use
        switch (algorithm) {
        case AES_ECB:
            for (int i = 0; i < c_len; i += AES_BLOCK_SIZE) {
                AES_encrypt(modifiablePlaintext + i, modifiablePlaintext + i, &encryptKey);
            }
            break;
        case AES_CBC:
            unsigned char iv_enc[AES_BLOCK_SIZE];
            memcpy(iv_enc, this->iv, AES_BLOCK_SIZE);  // Copy IV

            for (int i = 0; i < c_len; i += AES_BLOCK_SIZE) {
                for (int j = 0; j < AES_BLOCK_SIZE; ++j) {
                    modifiablePlaintext[i + j] ^= iv_enc[j];
                }
                AES_encrypt(modifiablePlaintext + i, modifiablePlaintext + i, &encryptKey);
                memcpy(iv_enc, modifiablePlaintext + i, AES_BLOCK_SIZE); // Update IV
            }
            break;
        }

        string result(reinterpret_cast<char*>(modifiablePlaintext), c_len);
        delete[] modifiablePlaintext;
        return result;
    }

    // Decrypts the ciphertext
    string decrypt(const unsigned char* ciphertext, int length) {
        unsigned char* modifiableCiphertext = new unsigned char[length];
        memcpy(modifiableCiphertext, ciphertext, length);

        switch (algorithm) {
        case AES_ECB:
            for (int i = 0; i < length; i += AES_BLOCK_SIZE) {
                AES_decrypt(ciphertext + i, modifiableCiphertext + i, &decryptKey);
            }
            break;
        case AES_CBC:
            unsigned char iv_dec[AES_BLOCK_SIZE];
            memcpy(iv_dec, this->iv, AES_BLOCK_SIZE);  // Copy IV

            for (int i = 0; i < length; i += AES_BLOCK_SIZE) {
                unsigned char temp[AES_BLOCK_SIZE];
                memcpy(temp, ciphertext + i, AES_BLOCK_SIZE); // Save current block
                AES_decrypt(ciphertext + i, modifiableCiphertext + i, &decryptKey);
                for (int j = 0; j < AES_BLOCK_SIZE; ++j) {
                    modifiableCiphertext[i + j] ^= iv_dec[j];
                }
                memcpy(iv_dec, temp, AES_BLOCK_SIZE); // Update IV with saved block
            }
            break;
        }

        string result(reinterpret_cast<char*>(modifiableCiphertext), length);
        delete[] modifiableCiphertext;
        return result;
    }

    ~AESCipher() {

    }

private:
    AESAlgorithm algorithm;
    AES_KEY encryptKey, decryptKey;
    unsigned char iv[AES_BLOCK_SIZE];  // Initialization vector for CBC iv
};

int main() {

    // Symmetric AES keys for 128 bits
    unsigned char key[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0 };

    // Initialization Vector (IV) for encryption and decryption
    unsigned char iv[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                               0x01, 0x02, 0x03, 0x4, 0xff, 0xff, 0xff, 0xff };

    unsigned char plaintext[] = "Sebastian Craciun ISM";

    // Instantiate AESCipher for ECB mode
    AESCipher ecbCipher(AESCipher::AES_ECB, key);
    string encrypted_ecb = ecbCipher.encrypt(plaintext, sizeof(plaintext));

    // Create a modifiable copy of the encrypted data for decryption
    unsigned char* encrypted_ecb_copy = new unsigned char[encrypted_ecb.size()];
    memcpy(encrypted_ecb_copy, encrypted_ecb.data(), encrypted_ecb.size());

    // Use the copy for decryption
    string decrypted_ecb = ecbCipher.decrypt(encrypted_ecb_copy, encrypted_ecb.size());

    // Clean up the temporary buffer
    delete[] encrypted_ecb_copy;

    // Instantiate AESCipher for CBC mode
    AESCipher cbcCipher(AESCipher::AES_CBC, key, iv);
    string encrypted_cbc = cbcCipher.encrypt(plaintext, sizeof(plaintext));

    // Create a modifiable copy of the encrypted data for decryption
    unsigned char* encrypted_cbc_copy = new unsigned char[encrypted_cbc.size()];
    memcpy(encrypted_cbc_copy, encrypted_cbc.data(), encrypted_cbc.size());

    // Use the copy for decryption
    string decrypted_cbc = cbcCipher.decrypt(encrypted_cbc_copy, encrypted_cbc.size());
    delete[] encrypted_cbc_copy;

    cout << "ECB Encrypted: " << encrypted_ecb << endl;
    cout << "ECB Decrypted: " << decrypted_ecb << endl;
    cout << "CBC Encrypted: " << encrypted_cbc << endl;
    cout << "CBC Decrypted: " << decrypted_cbc << endl;

    return 0;
}
