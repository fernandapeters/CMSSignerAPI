#include <iostream>
#include <iomanip>

#include "CMSSigner.h"
#include "CMSVerifier.h"
#include "FileHash.h"

#include "CMSApplication.h"


int main(int argc, char* argv []) {
    CMSApplication app;
    return app.run(argc, argv);
    /*try {
        std::string filepath = "resources/doc.txt";
        std::string hash = crypto::file_hash::Sha512FileHash(filepath);
        std::cout << "SHA-512 hash of " << filepath << ":\n" << hash << std::endl;

        std::string pkcs12_path = "resources/certificado_teste_hub.pfx";
        std::string pkcs12_password = "bry123456";
        std::string cert_alias = "e2618a8b-20de-4dd2-b209-70912e3177f4";
        crypto::CMSSigner crypto_utils(pkcs12_path, pkcs12_password, cert_alias);

        std::vector<unsigned char> signature = crypto_utils.SignFile(filepath);
        if (!signature.empty()) {
            std::cout << "File signed successfully." << std::endl;
            std::cout <<  "Signature: ";
            for (unsigned char byte : signature) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            std::cout << std::endl;
        } else {
            std::cerr << "Failed to sign the file." << std::endl;
        }

        crypto::CMSVerifier verifier("resources/certificado_teste_hub.pfx", "bry123456");

        if (!verifier.InitializeTrustStore()) {
            std::cerr << "Failed to initialize trust store" << std::endl;
            return 1;
        }

        bool is_valid = verifier.VerifySignature("resources/doc.txt.p7s");
        std::cout << "\nSignature is " << (is_valid ? "VALID" : "INVALID") << std::endl;

        return is_valid ? 0 : 1;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;*/
}
