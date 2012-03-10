#ifndef INSTRUCTION_HPP
#define INSTRUCTION_HPP

#include <string>

class Instruction
{
    public:
        explicit Instruction(std::string disass, unsigned long long offset, unsigned int size);
        ~Instruction(void);

        unsigned long long get_absolute_address(unsigned char* ptr);

        unsigned int get_size(void) const;

        unsigned long long get_offset(void) const;

        std::string get_disassembly(void) const;

    private:
        std::string m_disass;
        unsigned long long m_offset;
        unsigned int m_size;
};

#endif