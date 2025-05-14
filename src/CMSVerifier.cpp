#include "CMSVerifier.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>

using namespace crypto;

    CMSVerifier::CMSVerifier(std::string pkcs12_path,
                             std::string pkcs12_password)
        : cert_path_(pkcs12_path),
          cert_password_(pkcs12_password),
          store_(nullptr)
    {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }

    CMSVerifier::~CMSVerifier() {
        if (store_) X509_STORE_free(store_);
    }

    bool CMSVerifier::InitializeTrustStore() {
        store_ = X509_STORE_new();
        if (!store_) {
            std::cerr << "Error creating X509 store" << std::endl;
            return false;
        }

        // Load trusted certificates
        FILE* fp = fopen(cert_path_.c_str(), "r");
        if (!fp) {
            std::cerr << "Error opening trusted certificate file" << std::endl;
            return false;
        }

        PKCS12* p12 = d2i_PKCS12_fp(fp, NULL);
        fclose(fp);
        if (!p12) {
            std::cerr << "Error reading PKCS12 file" << std::endl;
            return false;
        }
        EVP_PKEY* pkey_ = nullptr;
        X509* cert = nullptr;

        if (!PKCS12_parse(p12, cert_password_.c_str(), &pkey_, &cert, NULL)) {
            std::cerr << "Error parsing PKCS12 file (wrong password?)" << std::endl;
            PKCS12_free(p12);
            return false;
        }
        PKCS12_free(p12);

        if (X509_STORE_add_cert(store_, cert) != 1) {
            std::cerr << "Error adding certificate to trust store" << std::endl;
            X509_free(cert);
            return false;
        }

        X509_free(cert);
        return true;
    }

    bool CMSVerifier::VerifySignature(const std::string& signaturePath) {
        auto in = BIO_new_file(signaturePath.c_str(), "rb");
        if (!in) {
            std::cerr << "Error opening signature file" << std::endl;
            return false;
        }
        BIO *cont = nullptr;
        auto cms = SMIME_read_CMS(in, &cont);
        if(!cms) {
            std::cerr << "Error reading CMS signature " << std::endl;
            ERR_print_errors_fp(stderr);
            BIO_free(in);
            return false;
        }
        if(!CMS_verify(cms, nullptr, store_, cont, nullptr, CMS_NOVERIFY)) {
            std::cerr << "Error verifying CMS signature" << std::endl;
            ERR_print_errors_fp(stderr);
            BIO_free(in);
            BIO_free(cont);
            return false;
        }
        std::cout << "Signature verified successfully" << std::endl;
        BIO_free(in);
        BIO_free(cont);
        CMS_ContentInfo_free(cms);
        return true;
    }

    void CMSVerifier::printCertificateInfo(X509* cert) {
        std::cout << "\n=== Certificate Information ===" << std::endl;

        // Subject
        X509_NAME* subject = X509_get_subject_name(cert);
        std::cout << "Subject: " << nameToString(subject) << std::endl;

        // Issuer
        X509_NAME* issuer = X509_get_issuer_name(cert);
        std::cout << "Issuer: " << nameToString(issuer) << std::endl;

        // Serial Number
        ASN1_INTEGER* serial = X509_get_serialNumber(cert);
        BIGNUM* bn = ASN1_INTEGER_to_BN(serial, NULL);
        char* hex = BN_bn2hex(bn);
        std::cout << "Serial Number: " << hex << std::endl;
        OPENSSL_free(hex);
        BN_free(bn);

        // Validity Period
        ASN1_TIME* not_before = X509_get_notBefore(cert);
        ASN1_TIME* not_after = X509_get_notAfter(cert);
        std::cout << "Valid From: " << asn1TimeToString(not_before) << std::endl;
        std::cout << "Valid Until: " << asn1TimeToString(not_after) << std::endl;

        // Public Key Algorithm
        int pkey_nid = OBJ_obj2nid(X509_get0_tbs_sigalg(cert)->algorithm);
        std::cout << "Public Key Algorithm: " << OBJ_nid2ln(pkey_nid) << std::endl;

        // Signature Algorithm
        int sig_nid = X509_get_signature_nid(cert);
        std::cout << "Signature Algorithm: " << OBJ_nid2ln(sig_nid) << std::endl;

        // Extensions
        printExtensions(cert);
    }

    std::string CMSVerifier::nameToString(X509_NAME* name) {
        BIO* bio = BIO_new(BIO_s_mem());
        X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
        char* data;
        long len = BIO_get_mem_data(bio, &data);
        std::string result(data, len);
        BIO_free(bio);
        return result;
    }

    std::string CMSVerifier::asn1TimeToString(ASN1_TIME* time) {
        BIO* bio = BIO_new(BIO_s_mem());
        ASN1_TIME_print(bio, time);
        char* data;
        long len = BIO_get_mem_data(bio, &data);
        std::string result(data, len);
        BIO_free(bio);
        return result;
    }

    void CMSVerifier::printExtensions(X509* cert) {
        std::cout << "\nExtensions:" << std::endl;
        int count = X509_get_ext_count(cert);
        for (int i = 0; i < count; i++) {
            X509_EXTENSION* ext = X509_get_ext(cert, i);
            ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);

            char buf[256];
            OBJ_obj2txt(buf, sizeof(buf), obj, 0);
            std::string ext_name(buf);

            // Skip some basic extensions for brevity
            if (ext_name == "X509v3 Subject Key Identifier" ||
                ext_name == "X509v3 Authority Key Identifier" ||
                ext_name == "X509v3 Basic Constraints") {
                continue;
            }

            std::cout << "- " << ext_name << ": ";

            BIO* bio = BIO_new(BIO_s_mem());
            if (!X509V3_EXT_print(bio, ext, 0, 0)) {
                ASN1_STRING_print(bio, X509_EXTENSION_get_data(ext));
            }

            char* data;
            long len = BIO_get_mem_data(bio, &data);
            std::cout << std::string(data, len) << std::endl;
            BIO_free(bio);
        }
    }

