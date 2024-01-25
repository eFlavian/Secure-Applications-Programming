#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *file;
    long fileSize;
    unsigned char *buffer;

    // Open the file for binary reading
    file = fopen("example.txt", "rb");

    // Check if the file is opened successfully
    if (file == NULL) {
        perror("Error opening the file");
        return 1; // Return an error code
    }

    // Determine the file size
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the byte array
    buffer = (unsigned char *)malloc(fileSize);
    if (buffer == NULL) {
        perror("Error allocating memory");
        fclose(file);
        return 1; // Return an error code
    }

    // Read the entire file into the buffer
    fread(buffer, 1, fileSize, file);

    // Close the file
    fclose(file);

    // Now 'buffer' contains the file contents as a byte array
    // You can use 'fileSize' to determine the size of the array

    // Your code to process the byte array goes here

    // Don't forget to free the allocated memory when done
    free(buffer);

    return 0; // Return success
}
