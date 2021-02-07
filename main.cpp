// arpbuddy - copyright 2021
#include <ArpBuddy.h>

#include <iostream>

// Entry point
int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::cerr << "Usage: arpbuddy [interface]" << std::endl;
        return 1;
    }

    const char *ifaceName = argv[1];
    
    ArpBuddy::Config config;
    config.ifaceName = ifaceName;
    config.verbosity = 1;

    ArpBuddy buddy(config);
    if (!buddy.IsValid())
    {
        std::cerr << "ArpBuddy init error, aborting." << std::endl;
        return 1;
    }

    while (buddy.Update())
    {
    }

    return 0;
}
