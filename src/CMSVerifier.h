#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/pem.h>


namespace crypto {
    class CMSVerifier {
    public:
        CMSVerifier(std::string pkcs12_path,
                    std::string pkcs12_password);

        ~CMSVerifier();

        bool InitializeTrustStore();
        bool VerifySignature(const std::string& signaturePath);

    private:
        void printCertificateInfo(X509* cert);
        std::string nameToString(X509_NAME* name);
        std::string asn1TimeToString(ASN1_TIME* time);
        void printExtensions(X509* cert);

        X509_STORE* store_;
        std::string cert_path_;
        std::string cert_password_;
    };
}
