#include "gadget.hpp"
#include "coloshell.hpp"
#include "toolbox.hpp"

Gadget::Gadget()
: m_size(0)
{
}

Gadget::~Gadget(void)
{
    /* Avoid memory leaks */
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
    /* 
     * If we haven't any offset yet, it means this instruction is the first one added
     * thus, the offset of the gadget
     */
    if(m_offsets.size() == 0)
        m_offsets.push_back(p_instruction->get_offset());

    /* We push the instruction in the front because the back is reserved for the ending instruction */
    m_instructions.push_back(p_instruction);

    m_size += p_instruction->get_size();

    m_disassembly += p_instruction->get_disassembly() + " ; ";
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

std::list<Instruction*> Gadget::get_instructions(void)
{
    std::list<Instruction*> instrs(m_instructions);
    /* We don't want the ending instruction in the list */
    instrs.pop_back();

    return instrs;
}

void Gadget::search_specific_gadget(std::map<std::string, Gadget*> &g)
{
    std::cout << "here are the pop gadget: " << std::endl;
    for(std::map<std::string, Gadget*>::const_iterator it = g.begin(); it != g.end(); ++it)
    {
        std::list<Instruction*> instrs = it->second->get_instructions();
        if(instrs.size() == 1)
        {
            Instruction *last_instr = instrs.back();
            if(is_matching(last_instr->get_disassembly(), "pop e??"))
            {
                std::cout << "A gadget with pop eax start @" << (it->second->get_first_offset() + last_instr->get_offset()) << std::endl;
            }
        }
    }
    std::cout << "DONNNNNEEEEE" << std::endl;
}

Instruction* Gadget::get_ending_instruction(void)
{
    return m_instructions.back();
}
