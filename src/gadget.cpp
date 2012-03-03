#include "gadget.hpp"

Gadget::Gadget(const char* ins, const char* ops, unsigned int size)
: m_disassembly(ins), m_opcodes(ops), m_size(size)
{
}

Gadget::~Gadget(void)
{
}