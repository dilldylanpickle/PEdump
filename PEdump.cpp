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

    if (peFile.fail()) {
        std::cout << "Failed to read DOS header." << std::endl;
        return 1;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "This is not a valid executable." << std::endl;
        return 1;
    }

    // Jump to the PE header start
    peFile.seekg(dosHeader.e_lfanew, std::ios::beg);

    DWORD peSignature;
    peFile.read((char*)&peSignature, sizeof(DWORD));

    if (peFile.fail()) {
        std::cout << "Failed to read PE signature." << std::endl;
        return 1;
    }

    if (peSignature != IMAGE_NT_SIGNATURE) {
        std::cout << "This is not a valid PE file." << std::endl;
        return 1;
    }

    IMAGE_FILE_HEADER peHeader;
    peFile.read((char*)&peHeader, sizeof(IMAGE_FILE_HEADER));

    if (peFile.fail()) {
        std::cout << "Failed to read PE header." << std::endl;
        return 1;
    }

    // Print basic info about PE file
    std::cout << "Machine type: " << peHeader.Machine << std::endl;
    std::cout << "Number of sections: " << peHeader.NumberOfSections << std::endl;
    std::cout << "Time date stamp: " << peHeader.TimeDateStamp << std::endl;
    std::cout << "Pointer to symbol table: " << peHeader.PointerToSymbolTable << std::endl;
    std::cout << "Number of symbols: " << peHeader.NumberOfSymbols << std::endl;
    std::cout << "Size of optional header: " << peHeader.SizeOfOptionalHeader << std::endl;
    std::cout << "Characteristics: " << peHeader.Characteristics << std::endl;

    // Read the Optional Header
    IMAGE_OPTIONAL_HEADER optionalHeader;
    peFile.read((char*)&optionalHeader, sizeof(IMAGE_OPTIONAL_HEADER));

    if (peFile.fail()) {
        std::cout << "Failed to read optional header." << std::endl;
        return 1;
    }

    // Display Optional Header information
    std::cout << "Optional Header:" << std::endl;
    std::cout << "\tEntry Point: " << optionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "\tImage Base: " << optionalHeader.ImageBase << std::endl;
    // Add other fields as desired...

    // Read and display the section headers
    for (int i = 0; i < peHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader;
        peFile.read((char*)&sectionHeader, sizeof(IMAGE_SECTION_HEADER));

        if (peFile.fail()) {
            std::cout << "Failed to read section header " << i << std::endl;
            return 1;
        }

        std::cout << "Section " << i + 1 << ":" << std::endl;

        char sectionName[9] = {};
        memcpy(sectionName, sectionHeader.Name, 8);
        std::cout << "\tName: " << sectionName << std::endl;

        std::cout << "\tVirtual Size: " << sectionHeader.Misc.VirtualSize << std::endl;
        std::cout << "\tVirtual Address: " << sectionHeader.VirtualAddress << std::endl;
        std::cout << "\tSize of Raw Data: " << sectionHeader.SizeOfRawData << std::endl;
        std::cout << "\tPointer to Raw Data: " << sectionHeader.PointerToRawData << std::endl;
        // Add other fields as desired...
    }

    return 0;
}
