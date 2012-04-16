#ifndef PROGRAM_HPP
#define PROGRAM_HPP

#include <string>
#include <fstream>
#include <list>
#include <map>
#include <string>

#include "cpu.hpp"
#include "executable_format.hpp"

/*! \class Program
 *
 *  A program is the combination between two things: a CPU which will be used by the disassembler, 
 *  and an ExecutableFormat in order to correctly extract the code (to find cool stuff in)
 */
class Program
{
	public:

       /*!
         *  \brief Program instanciation requires a path where it can find your binary
         *   
         *  \param program_path: The path of your binary
         */
        explicit Program(const std::string & program_path, CPU::E_CPU arch = CPU::CPU_UNKNOWN);
		
        ~Program(void);

        /*!
         *  \brief Display information concerning the executable format (section address, entry point, stuff like that)
         *   
         *  \param lvl: Set the verbosity level you want
         */
        void display_information(VerbosityLevel lvl = VERBOSE_LEVEL_1);

        /*!
         *  \brief Find all the unique rop gadgets
         *   
         *  \param depth: Set the depth of the research (don't forget the ending instruction doesn't count -- so if you want only ending instruction, depth = 0)
         *  \param engine_display_option: You can give several display options passed directly to the disassembly engine (enable at&t syntax on beaegine for example)
         *
         *  \return The unique gadgets found
         */
        std::map<std::string, Gadget*> find_gadgets(unsigned int depth, unsigned int engine_display_option = 0);

        /*!
         *  \brief Find hex values in the section of the program
         *   
         *  \param hex_values: It is a pointer on where it can find the bytes to find in memory
         *  \param size: It is the size of the buffer hex_values
         */
        void search_and_display(const unsigned char *hex_values, unsigned int size);

    private:
        
        CPU* m_cpu; /*!< a pointer on the CPU used by your program*/
        
        ExecutableFormat* m_exformat; /*!< a pointer on the ExecutableFormat used by your program*/
        
        std::ifstream m_file; /*!< the file descriptor*/
};

#endif
