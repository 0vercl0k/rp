#include "beadisassembler.hpp"

#include <cstring>
#include <iostream>
#include <list>

struct Instruction
{
    Instruction(std::string disass, unsigned long long vaddr)
        : m_disass(disass), m_vaddr(vaddr)
    {}

    std::string m_disass;
    unsigned long long m_vaddr;
};

BeaDisassembler::BeaDisassembler(void)
{
    memset(&m_dis, 0, sizeof(DISASM));
    m_dis.Options = NasmSyntax + PrefixedNumeral + ShowSegmentRegs;
    m_dis.Archi = 0; //ia32
}

BeaDisassembler::~BeaDisassembler(void)
{
}

std::string BeaDisassembler::disassemble(unsigned char* data, unsigned int size, long long vaddr, unsigned int depth)
{
    int error = 0;
    unsigned int i = 0;
    DISASM ret_instr = {0};

    for(unsigned int offset = 0; offset < size; ++offset)
    {
        m_dis.EIP = (UIntPtr)(data + offset);
        m_dis.VirtualAddr = vaddr + offset;
        m_dis.SecurityBlock = size - offset;

        int len = Disasm(&m_dis);
        /* I guess we're done ! */
        if(len == OUT_OF_BLOCK)
            break;

        /* OK this one is an unknow opcode, goto the next one */
        if(len == UNKNOWN_OPCODE)
            continue;

        if(m_dis.Instruction.BranchType == RetType)
        {
            /* Okay I found a RET ; now I can build the gadget */
            //std::cout << "I found a RET @ " << std::hex << m_dis.VirtualAddr << std::endl;
            memcpy(&ret_instr, &m_dis, sizeof(DISASM));
            std::list<Instruction> gadget;
            
            /* The RET instruction is the latest of our instruction chain */
            gadget.push_front(Instruction(
                std::string(ret_instr.CompleteInstr),
                ret_instr.EIP
            ));

            for(unsigned int i = 0; i < depth; ++i)
            {
                bool is_valid_instruction = false;
                while(is_valid_instruction == false)
                {
                    m_dis.EIP--;
                    m_dis.VirtualAddr--;
                    
                    //TODO: Fix properly the security block
                    m_dis.SecurityBlock = 0;

                    int len_instr = Disasm(&m_dis);
                    if(len_instr == UNKNOWN_OPCODE)
                    {
                        /* If we have a first valid instruction, but the second one is unknown ; we return it even if its size is < depth */
                        if(gadget.size() > 0)
                            break;
                        else
                            continue;
                    }
                    
                    if(len_instr == OUT_OF_BLOCK)
                        break;

                    Instruction & last_instr = gadget.front();

                    /*
                        We don't want to reuse the opcode of the ret instruction to create a new one:
                           Example:
                            data = \xE9
                                   \x31
                                   \xC0
                                   \xC3
                                   \x00
                       So our ret is at data +3, we try to have a valid instruction with:
                        1] \xC0 ; but NOT \xC0\xC3
                        2] \x31\xC0
                        3] \xE9\x31\xC0
                        4] ...
                    */
                    if(m_dis.EIP + len_instr > last_instr.m_vaddr)
                        continue;

                    // We want consecutive gadget, not with a "hole" between them
                    if(m_dis.EIP + len_instr != last_instr.m_vaddr)
                        break;

                    gadget.push_front(Instruction(
                        std::string(m_dis.CompleteInstr),
                        m_dis.EIP
                    ));

                    if(gadget.size() == (depth + 1))
                        is_valid_instruction = true;
                }
            }

            if(gadget.size() > 1)
            {
                for(std::list<Instruction>::const_iterator it = gadget.begin(); it != gadget.end(); ++it)
                    std::cout << it->m_disass << " ; ";
                std::cout << std::endl;
            }
        }
    }

    return std::string("tg");
}