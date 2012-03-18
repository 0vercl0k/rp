#ifndef IA64_H
#define IA64_H

#include "cpu.hpp"

class Ia64 : public CPU
{
    public:
        explicit Ia64(void);
        ~Ia64(void);

        std::string get_class_name(void) const;

        std::map<std::string, Gadget*> find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size, const unsigned long long vaddr, const unsigned int depth);
};

#endif