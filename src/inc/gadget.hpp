#ifndef GADGET_HPP
#define GADGET_HPP

#include <list>
#include <string>
#include "instruction.hpp"

class Gadget
{
    public:
        explicit Gadget(void);
        ~Gadget(void);

        std::string get_disassembly(void) const;

        unsigned int get_size(void) const;
        
        void add_instruction(Instruction* p_instruction);

        unsigned long long get_va(void) const;

    private:
        std::string m_disassembly;
        unsigned int m_size;
        std::list<Instruction*> m_instructions;
};

#endif