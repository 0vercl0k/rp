#ifndef IA32_H
#define IA32_H

#include "cpu.hpp"

class Ia32 : public CPU
{
    public:
        explicit Ia32(void);
        ~Ia32(void);

        std::string get_class_name(void) const;
        
        std::vector<Gadget*> find_gadget_in_memory(unsigned char *p_memory, unsigned int size);

    private:
        std::vector<Gadget> m_gadgets;
};

#endif