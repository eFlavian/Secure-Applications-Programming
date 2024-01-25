#include <iostream>
#include <fstream>

int main() {
    // Sample byte array
    unsigned char byteArray[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // ASCII values for "Hello"

    // Open a binary file for writing
    std::ofstream outputFile("output.bin", std::ios::binary);

    // Check if the file is opened successfully
    if (!outputFile.is_open()) {
        std::cerr << "Error opening the file for writing!" << std::endl;
        return 1; // Return an error code
    }

    // Write the entire byte array to the file
    outputFile.write(reinterpret_cast<const char*>(byteArray), sizeof(byteArray));

    // Close the file
    outputFile.close();

    std::cout << "Binary file written successfully." << std::endl;

    return 0; // Return success
}
