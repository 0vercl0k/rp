/*
    This file is part of rp++.

    Copyright (C) 2013, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
    All rights reserved.

    rp++ is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    rp++ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with rp++.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "main.hpp"
#include "coloshell.hpp"
#include "program.hpp"
#include "toolbox.hpp"
#include "argtable2.h"
#include "BeaEngine.h"

#include <iostream>
#include <exception>
#include <cstdlib>
#include <cstring>

int main(int argc, char* argv[])
{
    struct arg_file *file    = arg_file0("f", "file", "<binary path>", "give binary path");
    struct arg_int  *display = arg_int0("i", "info", "<1,2,3>", "display information about the binary header");
    struct arg_int  *rop     = arg_int0("r", "rop", "<positive int>", "find useful gadget for your future exploits, arg is the gadget maximum size in instructions");
    struct arg_str  *raw     = arg_str0(NULL, "raw", "<archi>", "find gadgets in a raw file, 'archi' must be in the following list: x86, x64");
    struct arg_lit  *att     = arg_lit0(NULL, "atsyntax", "enable the at&t syntax");
    struct arg_lit  *unique  = arg_lit0(NULL, "unique", "display only unique gadget");
    struct arg_str  *shexa   = arg_str0(NULL, "search-hexa", "<\\x90A\\x90>", "try to find hex values");
    struct arg_str  *sint    = arg_str0(NULL, "search-int", "<int in hex>", "try to find a pointer on a specific integer value");
    struct arg_lit  *help    = arg_lit0("h", "help", "print this help and exit");
    struct arg_lit  *version = arg_lit0("v", "version", "print version information and exit");
    struct arg_end  *end     = arg_end(20);
    void* argtable[] = {file, display, rop, raw, att, unique, shexa, sint, help, version, end};

    if(arg_nullcheck(argtable) != 0)
        RAISE_EXCEPTION("Cannot allocate long option structures");

    int nerrors = arg_parse(argc, argv, argtable);
    if(nerrors > 0)
    {
        arg_print_errors(stdout, end, argv[0]);
        std::cout << "Try '" << argv[0] << " --help' for more information." << std::endl;
        return -1;
    }

    try
    {
        if(help->count > 0 || argc == 1)
        {
            w_yel_lf("DESCRIPTION:");
            w_red("rp++");
            std::cout << " allows you to find ROP gadgets in pe/elf/mach-o x86/x64 binaries." << std::endl;
            std::cout << "NB: The original idea comes from (@jonathansalwan) and his 'ROPGadget' tool." << std::endl << std::endl;
            
            w_yel_lf("USAGE:");
            std::cout << argv[0];
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
            CPU::E_CPU arch(CPU::CPU_UNKNOWN);

            if(raw->count > 0)
            {
                const char* architecture = raw->sval[0];

                if(std::strcmp(architecture, "x86") == 0)
                    arch = CPU::CPU_x86;
                else if(std::strcmp(architecture, "x64") == 0)
                    arch = CPU::CPU_x64;
                else
                    RAISE_EXCEPTION("You must use an architecture supported, read the help");
                
            }
            
            Program p(program_path, arch);
            
            if(display->count > 0)
            {
                if(display->ival[0] < VERBOSE_LEVEL_1 || display->ival[0] > VERBOSE_LEVEL_3)
                    display->ival[0] = VERBOSE_LEVEL_1;

                p.display_information((VerbosityLevel)display->ival[0]);
            }

            if(rop->count > 0)
            {

                unsigned int disass_engine_display_option = 0;

                if(att->count > 0)
                {
                    disass_engine_display_option += ATSyntax;
                    std::cout << "Using the AT&T syntax.." << std::endl;
                }
                else
                {
                    disass_engine_display_option += NasmSyntax;
                    std::cout << "Using the Nasm syntax.." << std::endl;
                }

                if(rop->ival[0] < 0)
                    rop->ival[0] = 0;

                if(rop->ival[0] > MAXIMUM_INSTRUCTION_PER_GADGET)
                    RAISE_EXCEPTION("You specified a maximum number of instruction too important for the --rop option");

                std::cout << std::endl << "Wait a few seconds, rp++ is looking for gadgets.." << std::endl;
                std::multiset<Gadget*, Gadget::Sort> all_gadgets = p.find_gadgets(rop->ival[0], disass_engine_display_option);
                std::cout << "A total of " << all_gadgets.size() << " gadgets found." << std::endl;
                if(unique->count > 0)
                {
                    std::map<std::string, Gadget*> unique_gadgets = only_unique_gadgets(all_gadgets);

                    std::cout << "You decided to keep only the unique ones, " << unique_gadgets.size() << " unique gadgets found." << std::endl;

                    /* Now we walk the gadgets found and set the VA */
                    for(std::map<std::string, Gadget*>::iterator it = unique_gadgets.begin(); it != unique_gadgets.end(); ++it)
                    {                
                        display_gadget_lf(it->second->get_first_absolute_address(), it->second);

                        /* Avoid mem leaks */
                        delete it->second;
                    }

                    unique_gadgets.clear();
                }
                else
                {
                    for(std::multiset<Gadget*, Gadget::Sort>::iterator it = all_gadgets.begin(); it != all_gadgets.end(); ++it)
                    {
                        display_gadget_lf((*it)->get_first_absolute_address(), *it);
                    }
                }
            }

            if(shexa->count > 0)
            {
                unsigned int size = 0;
                unsigned char* hex_values = string_to_hex(shexa->sval[0], &size);
             
                if(hex_values == NULL)
                    RAISE_EXCEPTION("Cannot allocate hex_values");

                p.search_and_display(hex_values, size);
                delete[] hex_values;
            }
            
            if(sint->count > 0)
            {
                unsigned int val = std::strtoul(sint->sval[0], NULL, 16);
                p.search_and_display((const unsigned char*)&val, sizeof(unsigned int));
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
