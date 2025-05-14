#pragma once

#include <string>
#include <openssl/pem.h>
#include <vector>

namespace crypto {
    class CMSSigner {
    public:
        CMSSigner(const std::string& pkcs12_path,
                    const std::string& pkcs12_password,
                    const std::string& cert_alias);
        ~CMSSigner();

        std::vector<unsigned char> SignFile(const std::string& filepath);


    private:
        bool loadKeys();

        std::string pkcs12_path_;
        std::string pkcs12_password_;
        std::string cert_alias_;
        X509* cert_;
        EVP_PKEY* pkey_;
        X509_STORE* store_;
    };
}
