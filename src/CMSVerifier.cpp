#include "CMSVerifier.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>

using namespace crypto;

    CMSVerifier::CMSVerifier()
        : store_(nullptr),
          signatureInfo_("") {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }

    CMSVerifier::~CMSVerifier() {
        if (store_) X509_STORE_free(store_);
    }

    bool CMSVerifier::initializeTrustStore() {
        store_ = X509_STORE_new();
        if (!store_) {
            std::cerr << "Error creating X509 store" << std::endl;
            return false;
        }
        return true;
    }

    bool CMSVerifier::VerifySignature(const std::string& signaturePath) {
        initializeTrustStore();
        if (!store_) {
            std::cerr << "Trust store not initialized" << std::endl;
            return false;
        }

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

        signatureInfo_ = getSignatureInfo(cms);

        BIO_free(in);
        BIO_free(cont);
        CMS_ContentInfo_free(cms);
        return true;
    }

    std::string CMSVerifier::getSignatureInfo(CMS_ContentInfo* cms) {
        if (!cms) {
            std::cerr << "Invalid CMS content info" << std::endl;
            return "";
        }

        STACK_OF(X509)* signers = CMS_get0_signers(cms);
        if (!signers) {
            std::cerr << "Error retrieving signers from CMS" << std::endl;
            ERR_print_errors_fp(stderr);
            return "";
        }

        std::string result;
        for (int i = 0; i < sk_X509_num(signers); ++i) {
            X509* signer = sk_X509_value(signers, i);
            result += "Certificate Info:\n";
            result += "Subject: " + nameToString(X509_get_subject_name(signer)) + "\n";
            result += "Issuer: " + nameToString(X509_get_issuer_name(signer)) + "\n";

            X509_NAME* subjectName = X509_get_subject_name(signer);
            int cnIndex = X509_NAME_get_index_by_NID(subjectName, NID_commonName, -1);
            if (cnIndex >= 0) {
                X509_NAME_ENTRY* cnEntry = X509_NAME_get_entry(subjectName, cnIndex);
                ASN1_STRING* cnData = X509_NAME_ENTRY_get_data(cnEntry);
                result += "Signer Name (CN): " + std::string((char*)ASN1_STRING_get0_data(cnData)) + "\n";
            }

            const X509_ALGOR* sigAlg = X509_get0_tbs_sigalg(signer);
            const ASN1_OBJECT* algObj = nullptr;
            X509_ALGOR_get0(&algObj, nullptr, nullptr, sigAlg);
            result += "Signature Algorithm: " + std::string(OBJ_nid2ln(OBJ_obj2nid(algObj))) + "\n";

            unsigned char hash[SHA256_DIGEST_LENGTH];
            unsigned int hashLen;
            if (X509_digest(signer, EVP_sha256(), hash, &hashLen)) {
                result += "Hash: ";
                for (unsigned int j = 0; j < hashLen; ++j) {
                    char hexBuffer[3];
                    sprintf(hexBuffer, "%02x", hash[j]);
                    result += hexBuffer;
                }
                result += "\n";
            } else {
                std::cerr << "Error calculating hash" << std::endl;
            }

            // Getting signing time
            ASN1_TIME* signingTime = nullptr;
            STACK_OF(CMS_SignerInfo)* signersInfo = CMS_get0_SignerInfos(cms);
            if (signersInfo) {
                CMS_SignerInfo* signerInfo = sk_CMS_SignerInfo_value(signersInfo, i);
                if (signerInfo) {
                    signingTime = (ASN1_TIME*)CMS_signed_get0_data_by_OBJ(
                        signerInfo, OBJ_nid2obj(NID_pkcs9_signingTime), -3, V_ASN1_UTCTIME);
                    if (signingTime) {
                        char timeBuffer[64];
                        BIO* timeBio = BIO_new(BIO_s_mem());
                        if (ASN1_TIME_print(timeBio, signingTime)) {
                            char* timeData;
                            long timeLen = BIO_get_mem_data(timeBio, &timeData);
                            result += "Signing Time: " + std::string(timeData, timeLen) + "\n";
                        } else {
                            std::cerr << "Error formatting signing time" << std::endl;
                        }
                        BIO_free(timeBio);
                    } else {
                        std::cerr << "Error retrieving signing time" << std::endl;
                    }
                }
            }

        }

        sk_X509_free(signers);
        return result;
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

