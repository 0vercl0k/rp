#include "beadisassembler.hpp"

#include <cstring>

BeaDisassembler::BeaDisassembler(void)
{
    memset(&m_dis, 0, sizeof(DISASM));
    m_dis.Options = NasmSyntax + PrefixedNumeral + ShowSegmentRegs;
    m_dis.Archi = 0; //ia32
}

BeaDisassembler::~BeaDisassembler(void)
{
}

std::list<Gadget*> BeaDisassembler::find_rop_gadgets(const unsigned char* data, unsigned long long size, unsigned long long vaddr, unsigned int depth)
{
    std::list<Gadget*> gadgets;
    int error = 0;
    DISASM ret_instr = {0};

    for(unsigned int offset = 0; offset < size; ++offset)
    {
        m_dis.EIP = (UIntPtr)(data + offset);
        m_dis.VirtualAddr = vaddr + offset;
        m_dis.SecurityBlock = (UInt32)(size - offset);

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
                offset,
                len
            ));

            for(unsigned int i = 0; i < depth; ++i)
            {
                bool is_valid_instruction = false;
                while(is_valid_instruction == false)
                {
                    /* We respect the limits of the buffer */
                    if(m_dis.EIP <= (UIntPtr)data)
                        break;

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
                    if(m_dis.EIP + len_instr > last_instr.get_absolute_address(data))
                        continue;

                    // We want consecutive gadget, not with a "hole" between them
                    if(m_dis.EIP + len_instr != last_instr.get_absolute_address(data))
                        break;

                    gadget.push_front(Instruction(
                        std::string(m_dis.CompleteInstr),
                        m_dis.EIP,
                        len_instr
                    ));

                    if(gadget.size() == (depth + 1))
                        is_valid_instruction = true;
                }
            }

            if(gadget.size() > 1)
            {
                Gadget * g = new Gadget();
                for(std::list<Instruction>::iterator it = gadget.begin(); it != gadget.end(); ++it)
                    g->add_instruction(new Instruction(*it));

                gadgets.push_back(g);
            }
        }
    }

    return gadgets;
}