#ifndef INSTRUCTION_HPP
#define INSTRUCTION_HPP

#include <string>

/*
    Each instruction instance holds a disassembly, an offset (where we can find it in memory) and a size
*/
class Instruction
{
    public:
        explicit Instruction(std::string disass, unsigned long long offset, unsigned int size);
        ~Instruction(void);

        unsigned long long get_absolute_address(const unsigned char* ptr);

        /* Obtain the size of this instruction */
        unsigned int get_size(void) const;

        /* Where I can find this instruction in memory */
        unsigned long long get_offset(void) const;

        /* Get the text representation of the instruction */
        std::string get_disassembly(void) const;

    private:
        std::string m_disass;
        unsigned long long m_offset;
        unsigned int m_size;
};

#endif