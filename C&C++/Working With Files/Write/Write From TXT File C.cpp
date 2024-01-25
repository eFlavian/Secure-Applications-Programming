#include <stdio.h>

int main() {
    // Sample byte array
    unsigned char byteArray[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // ASCII values for "Hello"

    // Open a file for writing
    FILE *outputFile = fopen("output.txt", "w");

    // Check if the file is opened successfully
    if (outputFile == NULL) {
        perror("Error opening the file for writing");
        return 1; // Return an error code
    }

    // Convert each byte to a character and write to the file
    for (size_t i = 0; i < sizeof(byteArray) / sizeof(byteArray[0]); ++i) {
        fprintf(outputFile, "%c", byteArray[i]);
    }

    // Close the file
    fclose(outputFile);

    printf("File written successfully.\n");

    return 0; // Return success
}
