#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/pem.h>
#include <openssl/cms.h>


namespace crypto {
    class CMSVerifier {
    public:
        CMSVerifier();

        ~CMSVerifier();

        bool VerifySignature(const std::string& signaturePath);
        const std::string& getSignatureInfo() const { return signatureInfo_; }

    private:
        bool initializeTrustStore();
        std::string getSignatureInfo(CMS_ContentInfo* cert);
        std::string nameToString(X509_NAME* name);

        X509_STORE* store_;
        std::string signatureInfo_;
    };
}
