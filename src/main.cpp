#include <iostream>
#include <iomanip>

#include "CMSSigner.h"
#include "CMSVerifier.h"
#include "FileHash.h"

#include "CMSApplication.h"


int main(int argc, char* argv []) {
    try
    {
        CMSApplication app;
        return app.run(argc, argv);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    return 0;
}
