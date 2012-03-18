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
        
        /*
            Each CPU class is able to find unique gadgets in [p_memory, p_memory+size] 

            NB: The vaddr field is actually used by the BeaEngine when it disassembles something like jmp instruction, it needs the original virtual address to
            give you disassemble correctly (indeed jmp instruction are relative)
        */
        virtual std::map<std::string, Gadget*> find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size, const unsigned long long vaddr, const unsigned int depth) = 0;

        /* The different architectures RP++ handles */
        enum E_CPU
        {
            CPU_IA32,
            CPU_IA64,
            CPU_UNKNOWN
        };
};

#endif