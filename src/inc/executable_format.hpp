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

        /* The format RP++ handles */
        enum E_ExecutableFormat
        {
            FORMAT_PE,
            FORMAT_ELF,
            FORMAT_UNKNOWN
        };

        explicit ExecutableFormat(void);
        virtual ~ExecutableFormat(void);

        /* In your executable format, you can find the CPU used */
        virtual CPU* get_cpu(std::ifstream &file) = 0;

        /* Display the verbosity level */
        virtual void display_information(VerbosityLevel lvl)
        {
            std::cout << "Verbose level: " << verbosity_to_string(lvl) << std::endl;
        }

        /* Retrieves the class name, useful when using polymorphism */
        virtual std::string get_class_name(void) const = 0;

        /* Find the executable format used -- based mostly on the magic signature */
        static E_ExecutableFormat FindExecutableFormat(unsigned int magic_dword);

    private:

        /* Fill the structures you need, parse your executable format to extract the useful information */
        virtual CPU::E_CPU extract_information_from_binary(std::ifstream &file) = 0;
};

#endif