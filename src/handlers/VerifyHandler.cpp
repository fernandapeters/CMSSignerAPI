#include "VerifyHandler.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <Poco/Net/HTMLForm.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/PartHandler.h>
#include <Poco/StreamCopier.h>
#include <Poco/TemporaryFile.h>
#include <Poco/JSON/Object.h>
#include "../CMSVerifier.h"

using namespace Poco::Net;


class VerifyFileHandler : public PartHandler {
    public:
        std::string tempPath;

        VerifyFileHandler() {
            Poco::TemporaryFile tempFile;
            tempPath = tempFile.path();
            tempFile.keepUntilExit();
        }

        void handlePart(const MessageHeader& header, std::istream& stream) {
            for (const auto& field : header) {
                if(field.first == "Content-Disposition") {
                    std::string contentDisposition = field.second;

                    if (contentDisposition.find("signature") != std::string::npos) {
                        std::ofstream out(tempPath, std::ios::binary);
                        Poco::StreamCopier::copyStream(stream, out);
                    }
                }
            }
        }


        ~VerifyFileHandler() {
            std::remove(tempPath.c_str());
        }
    };


void VerifyRequestHandler::handleRequest(HTTPServerRequest& request, HTTPServerResponse& response) {
    try {
        VerifyFileHandler fileHandler;
        HTMLForm form(request, request.stream(), fileHandler);

        crypto::CMSVerifier verifier;

        bool isValid = verifier.VerifySignature(fileHandler.tempPath);

        response.setStatus(HTTPResponse::HTTP_OK);
        response.setContentType("application/json");

        Poco::JSON::Object json;
        json.set("Status", (isValid ? "VALID" : "INVALID") );
        json.set("Infos", verifier.getSignatureInfo());
        json.stringify(response.send());
    }
    catch (const std::exception& e) {
        response.setStatus(HTTPResponse::HTTP_BAD_REQUEST);
        response.setContentType("application/json");

        Poco::JSON::Object json;
        json.set("error", std::string(e.what()));
        json.stringify(response.send());
    }
}
