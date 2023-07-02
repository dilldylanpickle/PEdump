#include <iostream>
#include <fstream>
#include <windows.h>

int main(int argc, char* argv[]) {
    std::ifstream peFile;

    if (argc != 2) {
        std::cout << "Usage: PEdump <filename>" << std::endl;
        return 1;
    }

    peFile.open(argv[1], std::ios::binary);

    if (!peFile.is_open()) {
        std::cout << "Failed to open the file." << std::endl;
        return 1;
    }

    IMAGE_DOS_HEADER dosHeader;

    peFile.read((char*)&dosHeader, sizeof(IMAGE_DOS_HEADER));

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "This is not a valid executable." << std::endl;
        return 1;
    }

    std::cout << "PE file opened successfully." << std::endl;
    return 0;
}