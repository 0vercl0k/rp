#include "ia32.hpp"
#include "rpexception.hpp"
#include "beadisassembler.hpp"

#include <cstring>
#include <list>

Ia32::Ia32(void)
{
}

Ia32::~Ia32(void)
{
}

std::string Ia32::get_class_name(void) const
{
    return std::string("Ia32");
}

std::map<std::string, Gadget*> Ia32::find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size, const unsigned long long vaddr, const unsigned int depth)
{
    std::map<std::string, Gadget*> unique_gadgets;
    
    BeaDisassembler bea(BeaDisassembler::IA32, depth);
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