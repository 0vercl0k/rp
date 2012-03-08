#ifndef IA32_H
#define IA32_H

#include "cpu.hpp"

class Ia32 : public CPU
{
    public:
        explicit Ia32(void);
        ~Ia32(void);

        std::string get_class_name(void) const;
        
        std::map<std::string, Gadget*> find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size);

    private:
        std::vector<Gadget> m_gadgets;
};

#endif