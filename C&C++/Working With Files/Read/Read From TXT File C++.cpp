#include <iostream>
#include <fstream>
#include <string>

int main() {
    // Open a file for reading
    std::ifstream inputFile("example.txt");

    // Check if the file is opened successfully
    if (!inputFile.is_open()) {
        std::cerr << "Error opening the file!" << std::endl;
        return 1; // Return an error code
    }

    // Read and print the contents of the file line by line
    std::string line;
    while (std::getline(inputFile, line)) {
        std::cout << line << std::endl;
    }

    // Close the file
    inputFile.close();

    return 0; // Return success
}
