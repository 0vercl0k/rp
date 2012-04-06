#include "autorop.hpp"

AutoRop::AutoRop(void)
{
    m_list.push_back("int 0x80");
    m_list.push_back("inc eax");
    m_list.push_back("xor eax, eax");
    m_list.push_back("mov dword [eax], ebx");
    m_list.push_back("pop ebx");
}

AutoRop::~AutoRop(void)
{
}

void AutoRop::search_specific_gadget(std::map<std::string, Gadget*> &g)
{
    std::map<unsigned long long, std::string> results;

    for(std::vector<const char*>::const_iterator it_instr = m_list.begin(); it_instr != m_list.end(); ++it_instr)
    {
        for(std::map<std::string, Gadget*>::const_iterator it_gad = g.begin(); it_gad != g.end(); ++it_gad)
        {
            std::list<Instruction*> instrs = it_gad->second->get_instructions();
            if(instrs.size() == 1)
            {
                Instruction *last_instr = instrs.back();
                if(is_matching(last_instr->get_disassembly(), *it_instr))
                {
                    results.insert(std::make_pair(
                        last_instr->get_offset(),
                        *it_instr
                    ));
                }
            }
        }
    }

    if(results.size() == m_list.size())
    {
        std::cout << "that's cool, I've found all the gadget I needed!" << std::endl;
    }
    else
        std::cout << "fuuuuuuu" << std::endl;
}