#include <iostream>
#include <fstream>
#include <vector>

int main() {
    // Sample byte array
    std::vector<unsigned char> byteArray = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // ASCII values for "Hello"

    // Open a file for writing
    std::ofstream outputFile("output.txt");

    // Check if the file is opened successfully
    if (!outputFile.is_open()) {
        std::cerr << "Error opening the file for writing!" << std::endl;
        return 1; // Return an error code
    }

    // Convert each byte to a character and write to the file
    for (unsigned char byte : byteArray) {
        outputFile.put(byte);
    }

    // Close the file
    outputFile.close();

    std::cout << "File written successfully." << std::endl;

    return 0; // Return success
}
