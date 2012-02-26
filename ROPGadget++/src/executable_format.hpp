#ifndef EXECUTABLE_FORMAT_H
#define EXECUTABLE_FORMAT_H

#include <string>
#include <fstream>
#include <iostream>

#include "cpu.hpp"
#include "toolbox.hpp"

class ExecutableFormat
{
    public:
        enum E_ExecutableFormat
        {
            FORMAT_PE,
            FORMAT_ELF,
            FORMAT_UNKNOWN
        };

        explicit ExecutableFormat(void);
        ~ExecutableFormat(void);

        virtual std::string get_class(void) = 0;
        virtual CPU* get_cpu(std::ifstream &file) = 0;
        virtual void display_information(VerbosityLevel lvl)
        {
            std::cout << "Verbose level: " << verbosity_to_string(lvl) << std::endl;
        }

        static E_ExecutableFormat FindExecutableFormat(unsigned int magic_dword);
};

#endif