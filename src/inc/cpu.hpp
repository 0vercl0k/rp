#ifndef CPU_H
#define CPU_H

#include <string>
#include <map>

#include "gadget.hpp"

class CPU
{
    public:
        explicit CPU(void);
        virtual ~CPU(void);

        virtual std::string get_class_name(void) const = 0;
        
        virtual std::map<std::string, Gadget*> find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size) = 0;

        /* The different architectures RP++ handles */
        enum E_CPU
        {
            CPU_IA32,
            CPU_IA64,
            CPU_UNKNOWN
        };
};

#endif