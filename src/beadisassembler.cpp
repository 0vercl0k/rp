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

std::list<Gadget*> BeaDisassembler::find_all_gadget_new_algo(const unsigned char* data, DISASM* d_ret, unsigned long long offset, unsigned int len)
{
    std::list<Gadget*> gadgets;

    // we go back at the longuest instruction possible (x86: max size = 15bytes)
    m_dis.EIP         = d_ret->EIP - m_depth*15;
    m_dis.VirtualAddr = d_ret->VirtualAddr - m_depth*15;

    //going back yeah, but not too much :))
    if(m_dis.EIP < (unsigned long long)data)
    {
        m_dis.EIP = (UIntPtr)data;
        m_dis.VirtualAddr = m_vaddr;
    }

    while(m_dis.EIP < d_ret->EIP)
    {
        std::list<Instruction> g;
        UIntPtr saved_eip = m_dis.EIP;
        bool is_a_valid_gadget = false;
        for(unsigned int nb_ins = 0; nb_ins < m_depth; nb_ins++)
        {
            int len_instr = Disasm(&m_dis);
            if(len_instr == UNKNOWN_OPCODE || is_valid_instruction(&m_dis) == false)
                break;

            g.push_back(Instruction(
                std::string(m_dis.CompleteInstr),
                m_dis.EIP - (UIntPtr)data,
                len_instr
            ));
            
            m_dis.EIP += len_instr;
            if(m_dis.EIP == d_ret->EIP)
            {
                is_a_valid_gadget = true;
                //I reach the ending instruction without depth instruction
                break;
            }

            if(m_dis.EIP > d_ret->EIP)
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
        m_dis.EIP = saved_eip + 1;
    }

    return gadgets;
}

std::list<Gadget*> BeaDisassembler::find_all_gadget_from_ret(const unsigned char* data, DISASM* d_ret, unsigned long long offset, unsigned int len)
{
    std::list<Gadget*> gadgets;
    std::list<Instruction> gadget;

    
    /* The RET instruction is the latest of our instruction chain */
    gadget.push_front(Instruction(
        std::string(d_ret->CompleteInstr),
        offset,
        len
    ));

    m_dis.EIP = d_ret->EIP;
    m_dis.VirtualAddr = d_ret->VirtualAddr;

    while(true)
    {
        if(gadget.size() >= (m_depth + 1))
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

        /*
            OK now we can filter the instruction allowed
             1] Only the last instruction must jmp/call/ret somewhere
             2] Other details: disallow the jmp far etc
        */
        if(is_valid_instruction(&m_dis))
        {
            gadget.push_front(Instruction(
                std::string(m_dis.CompleteInstr),
                m_dis.EIP - (unsigned long long)data,
                len_instr
            ));
        }
    }
    
    /* 
        Now I have the longest gadget (in term of instruction, <= depth),
        I can add the sub-gadget
        Example:
            longuest = xor ecx, ecx ; pop edx ; ret
            gadgets = [
                'xor ecx, ecx ; pop edx ; ret',
                'pop edx ; ret',
                'ret'
           ]
    */

    for(std::list<Instruction>::iterator it = gadget.begin(); it != gadget.end(); ++it)
    {
        Gadget *sub_gadget = new (std::nothrow) Gadget();
        if(sub_gadget == NULL)
            RAISE_EXCEPTION("Cannot allocate a gadget");

        for(std::list<Instruction>::iterator it2 = it; it2 != gadget.end(); ++it2)
            sub_gadget->add_instruction(new Instruction(*it2));

        gadgets.push_back(sub_gadget);
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

        if(is_valid_ending_instruction(&m_dis))
        {
            /* Okay I found a RET ; now I can build the gadget */
            memcpy(&ret_instr, &m_dis, sizeof(DISASM));

            std::list<Gadget*> gadgets = find_all_gadget_new_algo(data, &ret_instr, offset, len);
            for(std::list<Gadget*>::iterator it = gadgets.begin(); it != gadgets.end(); ++it)
                merged_gadgets.push_back(*it);
        }
    }

    std::cout << "A total of " << merged_gadgets.size() << " gadgets." << std::endl;
    return merged_gadgets;
}