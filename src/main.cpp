#include <iostream>
#include <exception>

#include "coloshell.hpp"
#include "platform.h"
#include "program.hpp"
#include "beadisassembler.hpp"

#define NUM_V "1.3.3.7"

#ifdef ARCH_X64
#define VERSION_TMP NUM_V " x64 built the " __DATE__ " " __TIME__
#else
#define VERSION_TMP NUM_V " x86 built the " __DATE__ " " __TIME__
#endif

#ifdef WINDOWS
#define VERSION VERSION_TMP " for Windows."
#else
#define VERSION VERSION_TMP " for Unix."
#endif

void display_version()
{
    std::cout << "VERSION: " << VERSION << std::endl;
}

void display_usage()
{
    std::cout << "USAGE: ./rp++ <file> TGSUCE\n" << std::endl;
}

int main(int argc, char* argv[])
{
    display_version();
    BeaDisassembler a;

    unsigned char buffer[] = "\xe9\x31\xc0\xc3\x00\xc2\xc2\x01\xDE\xc3\x13\x37";
    a.disassemble(buffer, sizeof(buffer), (long long)buffer, 3);
    /*
    if(argc != 2)
    {
        display_usage();
        return -1;
    }
    
    std::string program_path(argv[1]);
    try
    {
        Program p(program_path);
        p.display_information(VERBOSE_LEVEL_3);

        p.find_and_display_gadgets();
    }
    catch(const std::exception &e)
    {
        enable_color(COLO_RED);
        std::cout << e.what() << std::endl;
        disable_color();
    }
   */
    return 0;
}