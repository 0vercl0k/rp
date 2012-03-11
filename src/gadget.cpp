#include "gadget.hpp"

Gadget::Gadget(void)
: m_size(0)
{
}

Gadget::~Gadget(void)
{
    for(std::list<Instruction*>::iterator it = m_instructions.begin();
        it != m_instructions.end();
        ++it)
            delete *it;
}

std::string Gadget::get_disassembly(void) const
{
    return m_disassembly;
}

unsigned int Gadget::get_size(void) const
{
    return m_size;
}

void Gadget::add_instruction(Instruction* p_instruction)
{
    m_instructions.push_front(p_instruction);
    m_size += p_instruction->get_size();
    m_disassembly += p_instruction->get_disassembly();
    m_disassembly += " ; ";
}

unsigned long long Gadget::get_va(void) const
{
    return m_instructions.front()->get_offset();
}