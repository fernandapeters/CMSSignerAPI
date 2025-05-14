#include "../src/FileHash.h"
#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>

class FileHashTest : public ::testing::Test {
protected:
    std::string testFilePath = "test_file.txt";
    std::string emptyFilePath = "empty_file.txt";

    void SetUp() override {
        // Create a test file with known content
        std::ofstream testFile(testFilePath);
        testFile << "This is a test file for hashing.";
        testFile.close();

        // Create an empty test file
        std::ofstream emptyFile(emptyFilePath);
        emptyFile.close();
    }

    void TearDown() override {
        // Remove test files after testing
        std::remove(testFilePath.c_str());
        std::remove(emptyFilePath.c_str());
    }
};

TEST_F(FileHashTest, HashNonEmptyFile) {
    std::string expectedHash = "a87b3a39237e4bc6ce0b21a31518407d129624d36c634d71f5c465d605d12bac"
                               "6726bd81fe3eaec8842226542072d46f940e74de3fc7e6ceb1c049499256e2de";

    EXPECT_NO_THROW({
        std::string hash = crypto::file_hash::Sha512FileHash(testFilePath);
        EXPECT_EQ(hash, expectedHash);
    });
}

TEST_F(FileHashTest, HashEmptyFile) {
    std::string expectedHash = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                               "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    EXPECT_NO_THROW({
        std::string hash = crypto::file_hash::Sha512FileHash(emptyFilePath);
        EXPECT_EQ(hash, expectedHash);
    });
}

TEST_F(FileHashTest, FileNotFound) {
    EXPECT_THROW({
        crypto::file_hash::Sha512FileHash("nonexistent_file.txt");
    }, std::runtime_error);
}
