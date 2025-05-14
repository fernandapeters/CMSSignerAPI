#pragma once

#include <Poco/Util/ServerApplication.h>

using namespace Poco::Util;

class CMSApplication : public ServerApplication {
    protected:
        int main(const std::vector<std::string>&);
    };
