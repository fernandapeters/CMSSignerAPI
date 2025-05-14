#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>

#include "CMSSigner.h"

using namespace crypto;

CMSSigner::CMSSigner(const std::string& pkcs12_path,
                             const std::string& pkcs12_password,
                             const std::string& cert_alias)
    : pkcs12_path_(pkcs12_path),
      pkcs12_password_(pkcs12_password),
      cert_alias_(cert_alias),
      pkey_(nullptr),
      cert_(nullptr),
      store_(nullptr) {}

CMSSigner::~CMSSigner() {
    if (pkey_) {
        EVP_PKEY_free(pkey_);
    }
    if (cert_) {
        X509_free(cert_);
    }
    if (store_) {
        X509_STORE_free(store_);
    }
}


bool CMSSigner::loadKeys() {
    FILE* fp = fopen(pkcs12_path_.c_str(), "rb");
    if (!fp) {
        std::cerr << "Error opening PKCS12 file" << std::endl;
        return false;
    }

    PKCS12* p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (!p12) {
        std::cerr << "Error reading PKCS12 file" << std::endl;
        return false;
    }

    if (!PKCS12_parse(p12, pkcs12_password_.c_str(), &pkey_, &cert_, NULL)) {
        std::cerr << "Error parsing PKCS12 file (wrong password?)" << std::endl;
        PKCS12_free(p12);
        return false;
    }
    PKCS12_free(p12);


    X509_NAME* name = X509_get_subject_name(cert_);
    int loc = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (loc < 0) {
        std::cerr << "Certificate alias not found" << std::endl;
        return false;
    }

    X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, loc);
    ASN1_STRING* asn1 = X509_NAME_ENTRY_get_data(entry);
    std::string alias(reinterpret_cast<const char*>(ASN1_STRING_get0_data(asn1)),
                ASN1_STRING_length(asn1));

    store_ = X509_STORE_new();
    if (!store_) {
        std::cerr << "Error creating X509 store" << std::endl;
        return false;
    }

    if (!X509_STORE_add_cert(store_, cert_)) {
        std::cerr << "Error adding certificate to store" << std::endl;
        return false;
    }

    return true;
}

std::vector<unsigned char> CMSSigner::SignFile(const std::string& filepath) {
    if (!loadKeys()) {
        std::cerr << "Error loading keys" << std::endl;
        return {};
    }
    if (!pkey_ || !cert_ || !store_) {
        std::cerr << "Keys not loaded" << std::endl;
        return {};
    }

    auto in = BIO_new_file(filepath.c_str(), "rb");
    if (!in) {
        std::cerr << "Error opening file to sign" << std::endl;
        return {};
    }
    auto cms = CMS_sign(cert_, pkey_, NULL, in, CMS_STREAM);
    if (!cms) {
        std::cerr << "Error creating CMS structure" << std::endl;
        BIO_free(in);
        return {};
    }
    auto outFilepath = filepath + ".p7s";
    auto out = BIO_new_file(outFilepath.c_str(), "wb");
    if (!out) {
        std::cerr << "Error creating output file" << std::endl;
        CMS_ContentInfo_free(cms);
        BIO_free(in);
        return {};
    }
    if(!SMIME_write_CMS(out, cms, in, CMS_STREAM)) {
        std::cerr << "Error writing CMS to output file" << std::endl;
        BIO_free(out);
        CMS_ContentInfo_free(cms);
        BIO_free(in);
        return {};
    }

    std::ifstream file_stream(outFilepath, std::ios::binary);
    if (!file_stream) {
        std::cerr << "Error reading output file: " << outFilepath << std::endl;
        return {};
    }

    std::vector<unsigned char> outFileContent((std::istreambuf_iterator<char>(file_stream)),
                                            std::istreambuf_iterator<char>());


    BIO_free(out);
    BIO_free(in);
    CMS_ContentInfo_free(cms);

    return outFileContent;
}
