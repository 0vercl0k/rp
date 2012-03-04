#ifndef IA64_H
#define IA64_H

#include "cpu.hpp"

class Ia64 : public CPU
{
    public:
        explicit Ia64(void);
        ~Ia64(void);

        std::string get_class_name(void) const;

        std::vector<Gadget*> find_gadget_in_memory(unsigned char *p_memory, unsigned long long size);
};

#endif