#include "coloshell.hpp"
#include "platform.h"
#include "program.hpp"
#include "beadisassembler.hpp"
#include "toolbox.hpp"
#include "argtable2.h"

#include <iostream>
#include <exception>
#include <cstdlib>

#define NUM_V "0.1"

#ifdef ARCH_X64
#define VERSION_TMP NUM_V " x64 built the " __DATE__ " " __TIME__
#else
#define VERSION_TMP NUM_V " x86 built the " __DATE__ " " __TIME__
#endif

#ifdef WINDOWS
#define VERSION_TM VERSION_TMP " for Windows"
#else
#define VERSION_TM VERSION_TMP " for Unix"
#endif

#ifdef _DEBUG
#define VERSION VERSION_TM " (Debug)"
#else
#define VERSION VERSION_TM " (Release)"
#endif

int main(int argc, char* argv[])
{
    struct arg_file *file    = arg_file0("f", "file", "<binary path>", "give binary path");
    struct arg_int  *display = arg_int0("i", "info", "<0-2>", "display information concerning the elf/pe");
    struct arg_int  *rop     = arg_int0("r", "rop", "<positive int>", "find a bunch of gadgets usable in your future exploits (the maximum number of instruction in arg)");
    struct arg_str  *shexa   = arg_str0(NULL, "search-hexa", "<\\x90A\\x90>", "try to find hex values");
    struct arg_str  *sint    = arg_str0(NULL, "search-int", "<int in hex>", "try to find a pointer on a specific integer value");
    struct arg_lit  *help    = arg_lit0("h", "help", "print this help and exit");
    struct arg_lit  *version = arg_lit0("v", "version", "print version information and exit");
    struct arg_end  *end     = arg_end(20);
    void* argtable[] = {file, display, rop, shexa, sint, help, version, end};

    if(arg_nullcheck(argtable) != 0)
        RAISE_EXCEPTION("Cannot allocate long option structures");

    int nerrors = arg_parse(argc, argv, argtable);
    if(nerrors > 0)
    {
        arg_print_errors(stdout, end, "rp++");
        std::cout << "Try './rp++ --help' for more information." << std::endl;
        return -1;
    }

    try
    {
        if(help->count > 0 || argc == 1)
        {
            w_yel_lf("DESCRIPTION:");
            w_red("rp++");
            std::cout << " is a very simple tool with a very simple purpose:" << std::endl << "  -> helping you to find interesting gadget in pe/elf x86/x64 binaries." << std::endl;
            std::cout << "NB: The original idea goes to Jonathan Salwan and its 'ROPGadget' tool." << std::endl << std::endl;
            
            w_yel_lf("USAGE:");
            std::cout << "./rp++";
            arg_print_syntax(stdout, argtable, "\n");

            std::cout << std::endl;
            w_yel_lf("OPTIONS:");
            arg_print_glossary(stdout, argtable, "  %-25s %s\n");
        }

        if(version->count > 0)
            std::cout << "You are currently using the version " << VERSION << " of rp++." << std::endl;

        /* If we've asked the help or version option, we assume the program is terminated */
        if(version->count > 0 || help->count > 0)
            return 0;

        if(file->count > 0)
        {
            std::string program_path(file->filename[0]);
            Program p(program_path);
            
            if(display->count > 0)
            {
                if(display->ival[0] < 0 || display->ival[0] > 2)
                    display->ival[0] = 0;

                p.display_information((VerbosityLevel)display->ival[0]);
            }

            if(rop->count > 0)
            {
                if(rop->ival[0] < 0)
                    rop->ival[0] = 0;

                p.find_and_display_gadgets(rop->ival[0]);
            }

            if(shexa->count > 0)
                p.search_and_display(shexa->sval[0]);
            
            if(sint->count > 0)
            {
                unsigned int val = std::strtoul(sint->sval[0], NULL, 16);
                p.search_and_display(val);
            }
        }
    }
    catch(const std::exception &e)
    {
        enable_color(COLO_RED);
        std::cout << e.what() << std::endl;
        disable_color();
    }

    return 0;
}