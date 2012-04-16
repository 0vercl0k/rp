#ifndef IA32_H
#define IA32_H

#include <vector>
#include "cpu.hpp"

class Ia32 : public CPU
{
    public:

        explicit Ia32(void);
        
        ~Ia32(void);

        std::string get_class_name(void) const;
        
        std::list<Gadget*> find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size, const unsigned long long vaddr, const unsigned int depth, unsigned int engine_display_option = 0);

    private:
        
        std::vector<Gadget> m_gadgets;
};

#endif
