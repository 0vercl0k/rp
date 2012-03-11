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

std::map<std::string, Gadget*> Ia32::find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size)
{
    std::map<std::string, Gadget*> unique_gadgets;
    BeaDisassembler bea;
    std::list<Gadget*> gadgets = bea.find_rop_gadgets(p_memory, size, (unsigned long long)p_memory);

    return unique_gadgets;
}