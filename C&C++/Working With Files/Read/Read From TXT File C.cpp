#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *file;
    char *buffer;
    size_t fileSize;

    // Open the file for reading
    file = fopen("example.txt", "r");

    // Check if the file is opened successfully
    if (file == NULL) {
        perror("Error opening the file");
        return 1; // Return an error code
    }

    // Determine the file size
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the buffer (plus one for the null terminator)
    buffer = (char *)malloc(fileSize + 1);
    if (buffer == NULL) {
        perror("Error allocating memory");
        fclose(file);
        return 1; // Return an error code
    }

    // Read the entire file into the buffer
    fread(buffer, 1, fileSize, file);

    // Null-terminate the buffer
    buffer[fileSize] = '\0';

    // Close the file
    fclose(file);

    // Now 'buffer' contains the file contents as a null-terminated string
    // You can use 'fileSize' to determine the size of the string

    // Your code to process the text goes here

    // Don't forget to free the allocated memory when done
    free(buffer);

    return 0; // Return success
}
