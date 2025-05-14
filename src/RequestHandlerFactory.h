#pragma once

#include <Poco/Net/HTTPRequestHandlerFactory.h>

using namespace Poco::Net;

class RequestHandlerFactory : public HTTPRequestHandlerFactory {
    public:
    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request) override;
};
