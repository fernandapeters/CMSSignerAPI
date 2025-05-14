#include "FileHash.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <openssl/pem.h>

namespace crypto::file_hash
{

    std::string Sha512FileHash(const std::string& filepath) {
        SHA512_CTX shaContext;
        if (!SHA512_Init(&shaContext)) {
            throw std::runtime_error("Failed to initialize SHA-512 context");
        }

        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file: " + filepath);
        }

        const size_t bufferSize = 4096;
        char buffer[bufferSize];
        while (file.read(buffer, bufferSize) || file.gcount()) {
            if (!SHA512_Update(&shaContext, buffer, file.gcount())) {
                throw std::runtime_error("Failed to update SHA-512 hash");
            }
        }

        unsigned char hash[SHA512_DIGEST_LENGTH];
        if (!SHA512_Final(hash, &shaContext)) {
            throw std::runtime_error("Failed to finalize SHA-512 hash");
        }

        std::ostringstream hexStream;
        hexStream << std::hex << std::setfill('0');
        for (unsigned char byte : hash) {
            hexStream << std::setw(2) << static_cast<int>(byte);
        }

        return hexStream.str();
    }

} // namespace crypto::file_hash
