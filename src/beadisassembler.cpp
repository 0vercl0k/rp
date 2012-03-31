#include "beadisassembler.hpp"
#include "safeint.hpp"

#include <iostream>
#include <cstring>

BeaDisassembler::BeaDisassembler(Arch arch, unsigned int depth, unsigned long long vaddr)
: m_depth(depth), m_vaddr(vaddr)
{
    memset(&m_dis, 0, sizeof(DISASM));
    m_dis.Options = NasmSyntax + PrefixedNumeral ;//+ ShowSegmentRegs;
    m_dis.Archi = arch;
}

BeaDisassembler::~BeaDisassembler(void)
{
}

std::list<Gadget*> BeaDisassembler::find_all_gadget_from_ret(const unsigned char* data, const DISASM* d_ret, unsigned long long offset, unsigned int len)
{
    std::list<Gadget*> gadgets;
    DISASM dis = {0};

    memcpy(&dis, &m_dis, sizeof(DISASM));

    /*
        We go back, trying to create the longuest gadget possible with the longuest instructions
        "On INTEL processors, (in IA-32 or intel 64 modes), instruction never exceeds 15 bytes." -- beaengine.org
    */
    dis.EIP         = (UIntPtr)(d_ret->EIP - m_depth*15); // /!\ Warning to pointer arith
    dis.VirtualAddr = d_ret->VirtualAddr - m_depth*15;

    //going back yeah, but not too much :))
    if(dis.EIP < (UIntPtr)data)
    {
        dis.EIP = (UIntPtr)data;
        dis.VirtualAddr = m_vaddr;
    }

    while(dis.EIP < d_ret->EIP)
    {
        std::list<Instruction> g;
        UIntPtr saved_eip  = dis.EIP;
        UInt64 saved_vaddr = dis.VirtualAddr;

        bool is_a_valid_gadget = false;
        for(unsigned int nb_ins = 0; nb_ins < m_depth; nb_ins++)
        {
            int len_instr = Disasm(&dis);
            if(len_instr == UNKNOWN_OPCODE || is_valid_instruction(&dis) == false)
                break;

            g.push_back(Instruction(
                std::string(dis.CompleteInstr),
                dis.EIP - (UIntPtr)data,
                len_instr
            ));
            
            dis.EIP += len_instr;
            dis.VirtualAddr += len_instr;
            if(dis.EIP == d_ret->EIP)
            {
                is_a_valid_gadget = true;
                //I reach the ending instruction without depth instruction
                break;
            }

            if(dis.EIP > d_ret->EIP)
                //next!
                break;
        }

        if(is_a_valid_gadget)
        {
            g.push_back(Instruction(
                std::string(d_ret->CompleteInstr),
                d_ret->EIP - (UIntPtr)data,
                len
            ));

            Gadget *gadget = new Gadget;
            for(std::list<Instruction>::iterator it = g.begin(); it != g.end(); ++it)
                gadget->add_instruction(new Instruction(*it));

            gadgets.push_back(gadget);
        }
        dis.EIP = saved_eip + 1;
        dis.VirtualAddr = saved_vaddr + 1;
    }

    return gadgets;
}

bool BeaDisassembler::is_valid_ending_instruction(DISASM* d)
{
    Int32 branch_type = d->Instruction.BranchType;
    UInt64 addr_value = d->Instruction.AddrValue;
    char *mnemonic = d->Instruction.Mnemonic;
    bool is_good_branch_type = (
        /* We accept all the ret type instructions (except retf/iret) */
        (branch_type == RetType && strncmp(mnemonic, "retf", 4) != 0 && strncmp(mnemonic, "iretd", 4) != 0) || 

        /* call reg32 / call [reg32] */
        (branch_type == CallType && addr_value == 0) ||

        /* jmp reg32 / jmp [reg32] */
        (branch_type == JmpType && addr_value == 0)
    );

    return (
        is_good_branch_type && 
        /* Yeah, entrance isn't allowed to the jmp far/call far */
        strstr(d->CompleteInstr, "far") == NULL
    );
}

bool BeaDisassembler::is_valid_instruction(DISASM *d)
{
    Int32 branch_type = d->Instruction.BranchType;
        return (
            branch_type != RetType && 
            branch_type != JmpType &&
            branch_type != CallType &&
            branch_type != JE &&
            branch_type != JB &&
            branch_type != JC &&
            branch_type != JO &&
            branch_type != JA &&
            branch_type != JS &&
            branch_type != JP &&
            branch_type != JL &&
            branch_type != JG &&
            branch_type != JNE &&
            branch_type != JNB &&
            branch_type != JNC &&
            branch_type != JNO &&
            branch_type != JECXZ &&
            branch_type != JNA &&
            branch_type != JNS &&
            branch_type != JNP &&
            branch_type != JNL &&
            branch_type != JNG &&
            branch_type != JNB &&
            strstr(d->CompleteInstr, "far") == NULL
        );
}

std::list<Gadget*> BeaDisassembler::find_rop_gadgets(const unsigned char* data, unsigned long long size, unsigned long long vaddr)
{
    std::list<Gadget*> merged_gadgets;

    /* 
        TODO:
        -> add function to check the jump instructions: je/jne/jc/jne/..

    */
    for(unsigned long long offset = 0; offset < size; ++offset)
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

        if(is_valid_ending_instruction(&m_dis))
        {
            /* Okay I found a RET ; now I can build the gadget */
            memcpy(&ret_instr, &m_dis, sizeof(DISASM));

            std::list<Gadget*> gadgets = find_all_gadget_from_ret(data, &ret_instr, offset, len);
            for(std::list<Gadget*>::iterator it = gadgets.begin(); it != gadgets.end(); ++it)
                merged_gadgets.push_back(*it);
        }
    }

    std::cout << "A total of " << merged_gadgets.size() << " gadgets." << std::endl;
    return merged_gadgets;
}