#include <stdio.h>

int main() {
    // Sample byte array
    unsigned char byteArray[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // ASCII values for "Hello"

    // Open a file for binary writing
    FILE *outputFile = fopen("output.bin", "wb");

    // Check if the file is opened successfully
    if (outputFile == NULL) {
        perror("Error opening the file for writing");
        return 1; // Return an error code
    }

    // Write the entire byte array to the file
    fwrite(byteArray, sizeof(byteArray[0]), sizeof(byteArray) / sizeof(byteArray[0]), outputFile);

    // Close the file
    fclose(outputFile);

    printf("Binary file written successfully.\n");

    return 0; // Return success
}
