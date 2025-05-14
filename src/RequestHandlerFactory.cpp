#include "RequestHandlerFactory.h"

#include <iostream>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include "handlers/SignHandler.h"
#include "handlers/VerifyHandler.h"

HTTPRequestHandler* RequestHandlerFactory::createRequestHandler(const HTTPServerRequest& request) {
    if (request.getURI() == "/signature/" && request.getMethod() == HTTPRequest::HTTP_POST) {
        return new SignRequestHandler;
    }
    else if (request.getURI() == "/verify/" && request.getMethod() == HTTPRequest::HTTP_POST) {
        return new VerifyRequestHandler;
    }
    return nullptr;
}
