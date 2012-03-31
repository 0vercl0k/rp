#ifndef PROGRAM_HPP
#define PROGRAM_HPP

#include <string>
#include <fstream>
#include <list>

#include "cpu.hpp"
#include "executable_format.hpp"

class Program
{
	public:
        explicit Program(const std::string & program_path);
		~Program(void);

        void display_information(VerbosityLevel lvl = VERBOSE_LEVEL_1);

        void find_and_display_gadgets(unsigned int depth);

        void search_and_display(const char *hex);
        void search_and_display(const unsigned int value);

    private:
        CPU* m_cpu;
        ExecutableFormat* m_exformat;
        std::ifstream m_file;
};

#endif