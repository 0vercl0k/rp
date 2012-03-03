#ifndef CPU_H
#define CPU_H

#include <string>
#include <vector>

#include "gadget.hpp"

class CPU
{
    public:
        explicit CPU(void);
        virtual ~CPU(void);

        virtual std::string get_class_name(void) const = 0;
        
        virtual std::vector<Gadget*> find_gadget_in_memory(unsigned char *p_memory, unsigned int size) = 0;

        /* The different architectures RP++ handles */
        enum E_CPU
        {
            CPU_IA32,
            CPU_IA64,
            CPU_UNKNOWN
        };
};

#endif