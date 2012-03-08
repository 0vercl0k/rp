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

std::map<std::string, Gadget*> Ia64::find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size)
{
    std::map<std::string, Gadget*> gadgets_found;
    return gadgets_found;
}