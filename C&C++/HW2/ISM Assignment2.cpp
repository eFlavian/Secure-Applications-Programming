#include <iostream>
#include <string>
#include <openssl/sha.h>
#include <openssl/md5.h>

using namespace std;

#define MESSAGE_CHUNK 256

class MessageDigest {
public:
    // static constants for supported algorithms
    static const string SHA256;
    static const string MD5;

    MessageDigest(const string algorithm) {
        this->algorithm = algorithm; // set the algorithm for this instance
    }

    // member function to compute message digest and return the hash as a string
    string computeDigest(string fileName) const {
        FILE* file = NULL;
        errno_t err = fopen_s(&file, fileName.c_str(), "rb");

        if (err == 0) {
            if (file) {
                if (this->algorithm == SHA256) {
                    return computeSHA256(file);
                }
                else if (this->algorithm == MD5) {
                    return computeMD5(file);
                }
                else {
                    fclose(file);
                    return "Error: Unsupported algorithm.";
                }

                fclose(file);
            }
            else {
                return "Error: File not found.";
            }
        }
        else {
            return "Error: Unable to open file.";
        }
    }

private:
    string algorithm; // algorithm for message digest computation

    // private function to compute SHA-256 hash
    string computeSHA256(FILE* file) const {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        unsigned char buffer[MESSAGE_CHUNK];
        size_t bytesRead;

        // read the file in chunks and update the SHA-256 context
        while ((bytesRead = fread(buffer, 1, MESSAGE_CHUNK, file)) > 0) {
            SHA256_Update(&ctx, buffer, bytesRead);
        }

        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256_Final(digest, &ctx);

        return getDigestString(digest, SHA256_DIGEST_LENGTH, "SHA-256");
    }

    // private function to compute MD5 hash
    string computeMD5(FILE* file) const {
        MD5_CTX ctx;
        MD5_Init(&ctx);

        unsigned char buffer[MESSAGE_CHUNK];
        size_t bytesRead;

        // read the file in chunks and update the MD5 context
        while ((bytesRead = fread(buffer, 1, MESSAGE_CHUNK, file)) > 0) {
            MD5_Update(&ctx, buffer, bytesRead);
        }

        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5_Final(digest, &ctx);

        return getDigestString(digest, MD5_DIGEST_LENGTH, "MD5");
    }

    // private utility function to format the hash as a string
    string getDigestString(const unsigned char* digest, int length, const string& algorithm) const {
        string result = algorithm + " = ";
        for (int i = 0; i < length; i++) {
            char hex[3];
            sprintf_s(hex, "%02X", digest[i]);
            result += hex;
        }
        result += "\n";
        return result;
    }
};

// initializing static members
const string MessageDigest::SHA256 = "SHA-256";
const string MessageDigest::MD5 = "MD5";

int main() {
    MessageDigest sha256Digest(MessageDigest::SHA256);
    MessageDigest md5Digest(MessageDigest::MD5);

    // computing and printing message digests
    cout << sha256Digest.computeDigest("input.txt");
    cout << md5Digest.computeDigest("input.txt");

    return 0;
}
