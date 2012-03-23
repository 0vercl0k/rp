#ifndef BEADISASSEMBLER_HPP
#define BEADISASSEMBLER_HPP

#define BEA_USE_STDCALL
#define BEA_ENGINE_STATIC

#include "BeaEngine.h"
#include "instruction.hpp"
#include "gadget.hpp"

#include <list>

/*
    This class aims to use the BeaEngine in order to find gadget in x86/x64 code.
*/
class BeaDisassembler
{
    public:
        enum Arch
        {
            IA32 = 0,
            IA64 = 64
        };

        explicit BeaDisassembler(Arch arch, unsigned int depth, unsigned long long vaddr);
        ~BeaDisassembler(void);

        /* This function returns the whole gadgets found in [data, data+size] ; it tries to find gadget with depth instruction (without the ret one) */
        std::list<Gadget*> find_rop_gadgets(const unsigned char* data, unsigned long long size, unsigned long long vaddr);

    private:
        std::list<Gadget*> find_all_gadget_from_ret(const unsigned char* data, DISASM* d_ret, unsigned long long offset, unsigned int len);
        bool is_valid_ending_instruction(DISASM* d);
        bool is_valid_instruction(DISASM *d);

        DISASM m_dis;
        unsigned int m_depth;
        unsigned long long m_vaddr;
};

#endif