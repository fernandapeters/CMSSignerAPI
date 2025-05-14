#include "../src/CMSVerifier.h"

#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>

class CMSVerifierTest : public ::testing::Test {
protected:
    std::string validPkcs12Path = "resources/certificado_teste_hub.pfx";
    std::string validPassword = "bry123456";
    std::string validSignaturePath = "resources/doc_signed.p7s";

    std::string invalidPkcs12Path = "resources/invalid_cert.pfx";
    std::string invalidPassword = "invalid_password";
    std::string invalidSignaturePath = "resources/invalid_signature.p7s";

    void SetUp() override {
        // Create dummy files for testing
        std::ofstream invalidCert(invalidPkcs12Path);
        invalidCert << "dummy invalid PKCS12 content";
        invalidCert.close();

        std::ofstream invalidSignature(invalidSignaturePath);
        invalidSignature << "dummy invalid signature content";
        invalidSignature.close();
    }

    void TearDown() override {
        // Remove dummy files after testing
        std::remove(invalidPkcs12Path.c_str());
        std::remove(invalidSignaturePath.c_str());
    }
};

TEST_F(CMSVerifierTest, InitializeTrustStore_Success) {
    crypto::CMSVerifier verifier(validPkcs12Path, validPassword);
    EXPECT_TRUE(verifier.InitializeTrustStore());
}

TEST_F(CMSVerifierTest, InitializeTrustStore_InvalidFile) {
    crypto::CMSVerifier verifier(invalidPkcs12Path, validPassword);
    EXPECT_FALSE(verifier.InitializeTrustStore());
}

TEST_F(CMSVerifierTest, InitializeTrustStore_InvalidPassword) {
    crypto::CMSVerifier verifier(validPkcs12Path, invalidPassword);
    EXPECT_FALSE(verifier.InitializeTrustStore());
}

TEST_F(CMSVerifierTest, VerifySignature_Success) {
    crypto::CMSVerifier verifier(validPkcs12Path, validPassword);
    ASSERT_TRUE(verifier.InitializeTrustStore());
    EXPECT_TRUE(verifier.VerifySignature(validSignaturePath));
}

TEST_F(CMSVerifierTest, VerifySignature_InvalidSignature) {
    crypto::CMSVerifier verifier(validPkcs12Path, validPassword);
    ASSERT_TRUE(verifier.InitializeTrustStore());
    EXPECT_FALSE(verifier.VerifySignature(invalidSignaturePath));
}

TEST_F(CMSVerifierTest, VerifySignature_FileNotFound) {
    crypto::CMSVerifier verifier(validPkcs12Path, validPassword);
    ASSERT_TRUE(verifier.InitializeTrustStore());
    EXPECT_FALSE(verifier.VerifySignature("nonexistent_file.p7s"));
}
