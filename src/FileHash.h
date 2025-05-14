#pragma once

#include <string>

namespace crypto {
    namespace file_hash {
        std::string Sha512FileHash(const std::string& filepath);
    }
}
