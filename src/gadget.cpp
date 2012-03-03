#include "gadget.hpp"

Gadget::Gadget(const char* ins, const char* ops, unsigned int size, unsigned int offset)
: m_disassembly(ins), m_opcodes(ops), m_size(size), m_offset(offset)
{
}

Gadget::~Gadget(void)
{
}

const char* Gadget::get_disassembly(void) const
{
    return m_disassembly;
}

unsigned int Gadget::get_offset(void) const
{
    return m_offset;
}

unsigned int Gadget::get_size(void) const
{
    return m_size;
}

const char* Gadget::get_opcodes(void) const
{
    return m_opcodes;
}