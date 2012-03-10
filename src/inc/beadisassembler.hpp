#ifndef BEADISASSEMBLER_HPP
#define BEADISASSEMBLER_HPP

#define BEA_USE_STDCALL
#define BEA_ENGINE_STATIC
#include "BeaEngine.h"

#include <string>

class BeaDisassembler
{
    public:
        explicit BeaDisassembler(void);
        ~BeaDisassembler(void);

        std::string disassemble(unsigned char* data, unsigned int size, long long vaddr, unsigned int depth = 1);

    private:
        DISASM m_dis;
};

#endif