#pragma once

#include <Poco/Net/HTTPRequestHandler.h>

class VerifyRequestHandler : public Poco::Net::HTTPRequestHandler {
    public:
        void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) override;
};
