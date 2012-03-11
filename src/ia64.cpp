#include "ia64.hpp"
#include "beadisassembler.hpp"

Ia64::Ia64(void)
{
}

Ia64::~Ia64(void)
{
}

std::string Ia64::get_class_name(void) const
{
    return std::string("Ia64");
}

std::map<std::string, Gadget*> Ia64::find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size, const unsigned long long vaddr)
{
    std::map<std::string, Gadget*> unique_gadgets;

    BeaDisassembler bea(BeaDisassembler::IA64);
    std::list<Gadget*> gadgets = bea.find_rop_gadgets(p_memory, size, vaddr);
    for(std::list<Gadget*>::iterator it = gadgets.begin(); it != gadgets.end(); ++it)
    {
        if(unique_gadgets.count((*it)->get_disassembly()) > 0)
        {
            std::map<std::string, Gadget*>::iterator g = unique_gadgets.find((*it)->get_disassembly());
            g->second->add_offset((*it)->get_first_offset());
        }
        else
        {
            unique_gadgets.insert(std::make_pair(
                (*it)->get_disassembly(),
                (*it)
                ));
        }
    }

    return unique_gadgets;
}