#include "beadisassembler.hpp"
#include "safeint.hpp"

#include <cstring>

BeaDisassembler::BeaDisassembler(Arch arch)
{
    memset(&m_dis, 0, sizeof(DISASM));
    m_dis.Options = NasmSyntax + PrefixedNumeral ;//+ ShowSegmentRegs;
    m_dis.Archi = arch;
}

BeaDisassembler::~BeaDisassembler(void)
{
}

std::list<Gadget*> BeaDisassembler::find_rop_gadgets(const unsigned char* data, unsigned long long size, unsigned long long vaddr, unsigned int depth)
{
    std::list<Gadget*> gadgets;
    /* 
        TODO:
        -> remove the jmp far
        -> remove the ret/call/jmp instruction except for the last one (don't want something like inc eax ; jmp [eax] ; stuff ;
    */
    for(unsigned int offset = 0; offset < size; ++offset)
    {
        m_dis.EIP = (UIntPtr)(data + offset);
        m_dis.VirtualAddr = SafeAddU64(vaddr, offset);
        m_dis.SecurityBlock = (UInt32)(size - offset);
        
        DISASM ret_instr = {0};

        int len = Disasm(&m_dis);
        /* I guess we're done ! */
        if(len == OUT_OF_BLOCK)
            break;

        /* OK this one is an unknow opcode, goto the next one */
        if(len == UNKNOWN_OPCODE)
            continue;

        if(
            /* We accept all the ret type instructions (except retf/iret) */
            (m_dis.Instruction.BranchType == RetType && strncmp(m_dis.Instruction.Mnemonic, "retf", 4) != 0 && strncmp(m_dis.Instruction.Mnemonic, "iretd", 4) != 0) || 
            /* call reg32 / call [reg32] */
            (m_dis.Instruction.BranchType == CallType && m_dis.Instruction.AddrValue == 0) ||
            /* jmp reg32 / jmp [reg32] */
            (m_dis.Instruction.BranchType == JmpType && m_dis.Instruction.AddrValue == 0)
          )
        {
            /* Okay I found a RET ; now I can build the gadget */
            memcpy(&ret_instr, &m_dis, sizeof(DISASM));
            std::list<Instruction> gadget;

            /* The RET instruction is the latest of our instruction chain */
            gadget.push_front(Instruction(
                std::string(ret_instr.CompleteInstr),
                offset,
                len
            ));

            while(true)
            {
                if(gadget.size() >= (depth + 1))
                    break;

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
                    if(gadget.size() > 1)
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
                    m_dis.EIP - (unsigned long long)data,
                    len_instr
                ));
            }
            
            Gadget * g = new (std::nothrow) Gadget();
            if(g == NULL)
                RAISE_EXCEPTION("Cannot allocate a gadget");

            for(std::list<Instruction>::iterator it = gadget.begin(); it != gadget.end(); ++it)
                g->add_instruction(new Instruction(*it));

            gadgets.push_back(g);
        }
    }

    return gadgets;
}