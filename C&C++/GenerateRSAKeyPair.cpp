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
