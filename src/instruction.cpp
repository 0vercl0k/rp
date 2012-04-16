#include "instruction.hpp"

Instruction::Instruction(std::string disass, std::string mnemonic, unsigned long long offset, unsigned int size)
: m_disass(disass), m_mnemonic(mnemonic), m_offset(offset), m_size(size)
{
}

Instruction::~Instruction(void)
{
}

unsigned long long Instruction::get_absolute_address(const unsigned char* va_section)
{
    return (unsigned long long)va_section + m_offset;
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

std::string Instruction::get_mnemonic(void) const
{
    return m_mnemonic;
}
