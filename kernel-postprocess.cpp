#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <sstream>


#define ADDRESS_LO 0xffffffff81000000
#define ADDRESS_HI 0xffffffff834e2f36
#define ADDRESS_SPACE_SIZE (ADDRESS_HI - ADDRESS_LO)

bool covered[ADDRESS_SPACE_SIZE];

int main(int argc, char* argv[]) {
    // Usage:
    // ./coverage <trace file> <kernel dump txt> <output txt>

    if (argc != 4) {
        std::cout << "Bad usage!\n";
        std::cout << "./coverage <trace file> <kernel dump txt> <output txt>\n";
        return 1;
    }

    char* trace_file = argv[1];
    char* kernel_dump = argv[2];
    char* output_file = argv[3];

    std::ifstream file(trace_file, std::ios::binary | std::ios::ate); // Set to the end, for file size
    if (!file) {
        std::cerr << "Error opening file " << trace_file << "\n";
        return 1;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);

    if (!file.read(buffer.data(), size)) {
        std::cerr << "Error reading file." << std::endl;
        return 1;
    }
    file.close();

    int count = 0;
    size_t index = 0;

    while (index + sizeof(uint32_t) + sizeof(uint16_t) <= size) {
        uint32_t start = *reinterpret_cast<uint32_t*>(&buffer[index]);
        uint16_t range = *reinterpret_cast<uint16_t*>(&buffer[index + sizeof(uint32_t)]);
        count++;

        index += sizeof(uint32_t) + sizeof(uint16_t);

        uint16_t i = 0;
        for (; i + 3 <= range; i += 4) {
            covered[start + i] = true;
            covered[start + i + 1] = true;
            covered[start + i + 2] = true;
            covered[start + i + 3] = true;
        }
        for (; i <= range; i++) {
            covered[start + i] = true;
        }

    }

    std::cout << "Total number of TBs in trace file: " << count << "\n";

    std::ifstream dumpFile(kernel_dump);
    if (!dumpFile) {
        std::cerr << "Error opening file " << kernel_dump << "\n";
        return 1;
    }

    std::ofstream outFile(output_file);
    if (!outFile) {
        std::cerr << "Error opening file " << output_file << "\n";
        return 1;
    }

	std::string line;

    while (std::getline(dumpFile, line)) {
        if (line.size() >= 17 && line[16] == ':') {
            uint64_t hexValue;
            std::stringstream ss;
            ss << std::hex << line.substr(0, 16);
            ss >> hexValue;

            if (covered[hexValue - ADDRESS_LO]) outFile << "y  " << line << "\n";
            else outFile << "n  " << line << "\n";
        } else {
            outFile << line << "\n"	;
        }
    }

    outFile.close();
    dumpFile.close();

    return 0;
}
