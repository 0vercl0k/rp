#include "instruction.hpp"

Instruction::Instruction(std::string disass, unsigned long long offset, unsigned int size)
: m_disass(disass), m_offset(offset), m_size(size)
{
}

Instruction::~Instruction(void)
{
}

unsigned long long Instruction::get_absolute_address(const unsigned char* ptr)
{
    return (unsigned long long)ptr + m_offset;
}


unsigned int Instruction::get_size(void) const
{
    return m_size;
}

unsigned long long Instruction::get_offset(void) const
{
    return m_offset;
}

std::string Instruction::get_disassembly(void) const
{
    return m_disass;
}