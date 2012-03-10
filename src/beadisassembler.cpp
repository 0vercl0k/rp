#include "beadisassembler.hpp"

#include <cstring>

BeaDisassembler::BeaDisassembler(void)
{
    memset(&m_dis, 0, sizeof(DISASM));
    m_dis.Options = NasmSyntax + PrefixedNumeral + ShowSegmentRegs;
}

BeaDisassembler::~BeaDisassembler(void)
{
}

std::string BeaDisassembler::disassemble(unsigned char* data, unsigned int size)
{
    std::string ret;
    int error = 0;

    m_dis.EIP = (UIntPtr)data;
    m_dis.SecurityBlock = size;
    
    while(error == 0)
    {
        unsigned int len = Disasm(&m_dis);
        switch(len)
        {
            case OUT_OF_BLOCK:
            case UNKNOWN_OPCODE:
            {
                error = 1;
                break;
            }

            default:
            {
                ret += m_dis.CompleteInstr;
                ret += "\n";
                m_dis.EIP += len;
                UIntPtr end = (UIntPtr)data + size;
                if(m_dis.EIP >= end)
                    error = 1;
            }
        }
    }

    return ret;
}