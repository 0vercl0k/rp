#include "ia32.hpp"
#include "rpexception.hpp"

#include <cstring>

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
    std::map<std::string, Gadget*> gadgets_found;
/*
    for(unsigned long long i = 0; i < size; ++i)
    {
        for(std::vector<Gadget>::iterator it = m_gadgets.begin(); it != m_gadgets.end(); ++it)
        {
            if(i + it->get_size() < i)
                RAISE_EXCEPTION("Integer overflow spotted!");

            if(i + it->get_size() <= size)
            {
                if(std::memcmp(it->get_opcodes(), p_memory + i, it->get_size()) == 0)
                {                   
                    if(gadgets_found.count(it->get_disassembly()) == 1)
                    {
                        std::map<std::string, Gadget*>::iterator p_gadget = gadgets_found.find(it->get_disassembly());
                        p_gadget->second->add_offset(i);
                    }
                    else
                    {
                        Gadget* gadget = new (std::nothrow) Gadget(
                            it->get_disassembly(),
                            it->get_opcodes(),
                            it->get_size(),
                            i
                            );

                        if(gadget == NULL)
                            RAISE_EXCEPTION("Cannot allocate a gadget.");

                        gadgets_found.insert(std::make_pair(
                            gadget->get_disassembly(),
                            gadget
                            ));
                    }
                }
            }
        }
    }
    */
    return gadgets_found;
}