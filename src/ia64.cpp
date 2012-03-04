#include "ia64.hpp"

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

std::vector<Gadget*> Ia64::find_gadget_in_memory(unsigned char *p_memory, unsigned long long size)
{
    std::vector<Gadget*> gadgets_found;
    return gadgets_found;
}