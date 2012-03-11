#ifndef BEADISASSEMBLER_HPP
#define BEADISASSEMBLER_HPP

#define BEA_USE_STDCALL
#define BEA_ENGINE_STATIC

#include "BeaEngine.h"
#include "instruction.hpp"
#include "gadget.hpp"

#include <list>

class BeaDisassembler
{
    public:
        explicit BeaDisassembler(void);
        ~BeaDisassembler(void);

        std::list<Gadget*> find_rop_gadgets(const unsigned char* data, unsigned long long size, unsigned long long vaddr, unsigned int depth = 1);

    private:
        DISASM m_dis;
};

#endif