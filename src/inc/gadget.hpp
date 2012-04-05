#ifndef GADGET_HPP
#define GADGET_HPP

#include <list>
#include <string>
#include <vector>
#include <map>

#include "instruction.hpp"

/*
    A gadget is a sequence of instructions that ends by a ret instruction (but sometimes by call/jmp)

    In order, to keep in memory only *unique* gadgets, each gadget holds a set of offset where you can find
    the same one.
*/
class Gadget
{
    public:
        explicit Gadget(Instruction* ending_instr);
        ~Gadget(void);

        /* Get entirely the disassembly of your gadget */
        std::string get_disassembly(void) const;

        /* Get the size of your gadget */
        unsigned int get_size(void) const;
        
        /* Add an instruction to your gadget */
        void add_instruction(Instruction* p_instruction);

        Instruction* get_ending_instruction(void);

        std::list<Instruction*> get_instructions(void);

        /* Get the first offset of this gadget */
        unsigned long long get_first_offset(void) const;

        /* Obtain the number of this specific gadget found */
        size_t get_nb(void) const;

        /* Add the offset where you can find the same gadget */
        void add_offset(unsigned long long offset);

        static void search_specific_gadget(std::map<std::string, Gadget*> &g);

    private:
        std::string m_disassembly;
        unsigned int m_size;
        Instruction *m_ending_instruction;
        std::list<Instruction*> m_instructions;
        std::vector<unsigned long long> m_offsets;
};

#endif