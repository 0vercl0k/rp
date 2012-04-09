#ifndef EXECUTABLE_FORMAT_H
#define EXECUTABLE_FORMAT_H

#include <string>
#include <fstream>
#include <iostream>
#include <vector>

#include "cpu.hpp"
#include "toolbox.hpp"
#include "section.hpp"
#include "rpexception.hpp"

/*! \class ExecutableFormat
 *
 *  An ExecutableFormat is the second part composing a Program instance ; it is required to parse correctly the binary file, to know
 *  where you can find its executable sections, etc.
 */
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

        /*!
         *  \brief Obtain the CPU ; for that it parses the executable format of your binary
         *   
         *  \return a pointer on the correct CPU
         */
        virtual CPU* get_cpu(std::ifstream &file) = 0;

        /*!
         *  \brief Display information concerning the executable format: where sections begin, entry point, etc.
         *
         *  \param lvl: Set a verbosity level
         */
        virtual void display_information(const VerbosityLevel lvl) const
        {
            std::cout << "Verbose level: " << verbosity_to_string(lvl) << std::endl;
        }

        /*!
         *  \brief Retrieve the name of the class, useful when using polymorphism
         *
         *  \return the class name
         */
        virtual std::string get_class_name(void) const = 0;

        /*!
         *  \brief Get the executable sections of you binary ; it is where we will look for gadgets
         *
         *  \param file: it is a file handle on your binary file
         *
         *  \return A vector of Section instances
         */
        virtual std::vector<Section*> get_executables_section(std::ifstream & file) = 0;

        /*!
         *  \brief A very useful method to do the conversion raw_offset (relative to a section) to virtual address (which is absolute) 
         *
         *   Example:
         *       offset = 0x10
         *       raw_section_offset = 0x100
         *
         *       virtual_section_offset = 0x1000
         *       raw_offset_to_va(offset, 0x100) will return 0x1010
         *
         *  \param absolute_raw_offset: It is the absolute raw offset you want to convert
         *  \param absolute_raw_offset_section: It is the aboslute raw offset of the section
         *
         *  \return The VA associated
         */
        virtual unsigned long long raw_offset_to_va(const unsigned long long absolute_raw_offset, const unsigned long long absolute_raw_offset_section) const = 0;

        /*!
         *  \brief Give you a PE/ELF instance (based mostly on the magic signature) 
         *
         *  \param magic_dword: It is a dword that allows to deduce which ExecutableFormat is used by the binary
         *
         *  \return A pointer on the correct ExecutableFormat deduced thanks to the magic_dword argument
         */
        static ExecutableFormat* GetExecutableFormat(unsigned int magic_dword);

    private:

        /*!
         *  \brief Fill the structures you need, parse your executable format to extract the useful information 
         *
         *  \param file: It is your binary file
         *
         *  \return The CPU type used in your binary file
         */
        virtual CPU::E_CPU extract_information_from_binary(std::ifstream &file)
        {
            RAISE_EXCEPTION("This method should not be called ; you're doing it wrong!");
            return CPU::CPU_UNKNOWN;
        }
};

#endif