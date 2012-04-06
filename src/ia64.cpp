#include "ia64.hpp"
#include "bearopgadgetfinder.hpp"

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

std::list<Gadget*> Ia64::find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size, const unsigned long long vaddr, const unsigned int depth)
{
    BeaRopGadgetFinder bea(BeaRopGadgetFinder::IA64, depth);
    std::list<Gadget*> gadgets = bea.find_rop_gadgets(p_memory, size, vaddr);
    return gadgets;
}