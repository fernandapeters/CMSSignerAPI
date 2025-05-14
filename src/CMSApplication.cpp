#include "CMSApplication.h"

#include <iostream>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/HTTPServerParams.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include "RequestHandlerFactory.h"

using namespace Poco::Net;

int CMSApplication::main(const std::vector<std::string>& args) {
    HTTPServerParams::Ptr params = new HTTPServerParams;
    params->setMaxQueued(100);
    params->setMaxThreads(16);

    uint16_t port = 8080;
    HTTPRequestHandlerFactory::Ptr factory = new RequestHandlerFactory;
    Poco::ThreadPool threadPool;
    HTTPServer server(factory, threadPool, ServerSocket(port), params);
    server.start();
    std::cout << "Server started on port "<< port << std::endl;
    std::cout << "Press Ctrl+C to stop the server..." << std::endl;
    waitForTerminationRequest();
    server.stop();

    return Application::EXIT_OK;
}

