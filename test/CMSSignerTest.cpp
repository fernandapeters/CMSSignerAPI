#include <gtest/gtest.h>
#include <fstream>
#include "../src/CMSSigner.h"

class CMSSignerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup paths and passwords for testing
        pkcs12_path = "resources/certificado_teste_hub.pfx";
        pkcs12_password = "bry123456";
        cert_alias = "testalias";
        test_file_path = "testfile.txt";

        // Create a test file
        std::ofstream test_file(test_file_path);
        test_file << "This is a test file for signing.";
        test_file.close();
    }

    void TearDown() override {
        // Clean up test files
        std::remove(test_file_path.c_str());
        std::remove((test_file_path + ".p7s").c_str());
    }

    std::string pkcs12_path;
    std::string pkcs12_password;
    std::string cert_alias;
    std::string test_file_path;
};

TEST_F(CMSSignerTest, LoadKeysFailureInvalidPath) {
    crypto::CMSSigner signer("/invalid/path.p12", pkcs12_password, cert_alias);
    EXPECT_TRUE(signer.SignFile(test_file_path).empty());
}

TEST_F(CMSSignerTest, LoadKeysFailureWrongPassword) {
    crypto::CMSSigner signer(pkcs12_path, "wrongpassword", cert_alias);
    EXPECT_TRUE(signer.SignFile(test_file_path).empty());
}

TEST_F(CMSSignerTest, SignFileSuccess) {
    crypto::CMSSigner signer(pkcs12_path, pkcs12_password, cert_alias);
    auto signature = signer.SignFile(test_file_path);
    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(std::ifstream(test_file_path + ".p7s").good());
}

TEST_F(CMSSignerTest, SignFileFailureInvalidFilePath) {
    crypto::CMSSigner signer(pkcs12_path, pkcs12_password, cert_alias);
    auto signature = signer.SignFile("/invalid/filepath.txt");
    EXPECT_TRUE(signature.empty());
}

TEST_F(CMSSignerTest, SignFileFailureKeysNotLoaded) {
    crypto::CMSSigner signer("", pkcs12_password, cert_alias);
    auto signature = signer.SignFile(test_file_path);
    EXPECT_TRUE(signature.empty());
}

