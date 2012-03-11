#ifndef GADGET_HPP
#define GADGET_HPP

#include <list>
#include <string>
#include <vector>

#include "instruction.hpp"

class Gadget
{
    public:
        explicit Gadget(void);
        ~Gadget(void);

        std::string get_disassembly(void) const;

        unsigned int get_size(void) const;
        
        void add_instruction(Instruction* p_instruction);

        unsigned long long get_first_offset(void) const;

        size_t get_nb(void) const;

        void add_offset(unsigned long long);

    private:
        std::string m_disassembly;
        unsigned int m_size;
        std::list<Instruction*> m_instructions;
        std::vector<unsigned long long> m_offsets;
};

#endif