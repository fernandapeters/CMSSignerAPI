#include "SignHandler.h"

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
#include "../CMSSigner.h"

using namespace Poco::Net;


class SignFilesHandler : public PartHandler {
    public:
        std::string tempPath;
        std::string certTempPath;

        SignFilesHandler() {
            Poco::TemporaryFile tempFileF, tempFileC;
            tempPath = tempFileF.path();
            certTempPath = tempFileC.path();
            tempFileF.keepUntilExit();
            tempFileC.keepUntilExit();
        }

        void handlePart(const MessageHeader& header, std::istream& stream) {
            for (const auto& field : header) {
                if(field.first == "Content-Disposition") {
                    std::string contentDisposition = field.second;

                    if (contentDisposition.find("cert") != std::string::npos) {
                        std::ofstream out(certTempPath, std::ios::binary);
                        Poco::StreamCopier::copyStream(stream, out);
                    }
                    else {
                        std::ofstream out(tempPath, std::ios::binary);
                        Poco::StreamCopier::copyStream(stream, out);
                    }
                }

            }

        }
        ~SignFilesHandler() {
            std::remove(tempPath.c_str());
            std::remove(certTempPath.c_str());
        }
    };


void SignRequestHandler::handleRequest(HTTPServerRequest& request, HTTPServerResponse& response) {
    try {
        SignFilesHandler fileHandler;
        HTMLForm form(request, request.stream(), fileHandler);

        std::string password = "";
        if (form.has("password")) {
            password = form.get("password");
         }

        crypto::CMSSigner signer(
            fileHandler.certTempPath,
            password,
            ""
        );

        std::vector<unsigned char> signature = signer.SignFile(fileHandler.tempPath);

        if (signature.empty()) {
            std::cerr << "Failed to sign the file." << std::endl;
            response.setStatus(HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            Poco::JSON::Object json;
            json.set("error", "Failed to sign the file");
            json.stringify(response.send());
            return;
        }

        response.setStatus(HTTPResponse::HTTP_OK);
        response.setContentType("application/json");

        Poco::JSON::Object json;
        json.set("signature", std::string(signature.begin(), signature.end()));
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
