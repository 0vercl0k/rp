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
    if(m_offsets.size() == 0)
        m_offsets.push_back(p_instruction->get_offset());

    m_instructions.push_front(p_instruction);
    m_size += p_instruction->get_size();
    m_disassembly += p_instruction->get_disassembly();
    m_disassembly += " ; ";
}

unsigned long long Gadget::get_first_offset(void) const
{
    return m_instructions.front()->get_offset();
}

size_t Gadget::get_nb(void) const
{
    return m_offsets.size();
}

void Gadget::add_offset(unsigned long long off)
{
    m_offsets.push_back(off);
}