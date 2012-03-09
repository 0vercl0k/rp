#include "gadget.hpp"

Gadget::Gadget(const char* ins, const char* ops, unsigned int size, unsigned long long offset)
: m_disassembly(ins), m_opcodes(ops), m_size(size)
{
    m_offsets.push_back(offset);
}

Gadget::~Gadget(void)
{
}

const char* Gadget::get_disassembly(void) const
{
    return m_disassembly;
}

std::vector<unsigned long long> Gadget::get_offsets(void) const
{
    return m_offsets;
}

unsigned int Gadget::get_size(void) const
{
    return m_size;
}

const char* Gadget::get_opcodes(void) const
{
    return m_opcodes;
}

void Gadget::add_offset(unsigned long long offset)
{
    m_offsets.push_back(offset);
}

unsigned long long Gadget::get_first_offset(void) const
{
    return m_offsets.at(0);
}

size_t Gadget::get_nb(void) const
{
    return m_offsets.size();
}