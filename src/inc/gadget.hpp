#ifndef GADGET_HPP
#define GADGET_HPP

#include <list>
#include <string>
#include <vector>
#include <map>

#include "instruction.hpp"

/*! \class Gadget
 *
 * A gadget is a sequence of instructions that ends by an ending instruction (ret/call/jmp)
 * In order, to keep in memory only *unique* gadgets, each gadget holds a set of offset where you can find
 * the same one.
 */
class Gadget
{
    public:

        explicit Gadget();

        ~Gadget(void);

        /*!
         *  \brief Get the entire disassembly of your gadget
         *  \return the disassembly
         */
        std::string get_disassembly(void) const;

        /*!
         *  \brief Get the size of your gadget
         *  \return the size of the whole gadget
         */
        unsigned int get_size(void) const;
        
        /*!
         *  \brief Add an instruction to your gadget ; don't forget it's back pushed in the instruction list
         *   It means the first instruction you'll insert will be the address of the gadget
         */
        void add_instruction(Instruction* p_instruction);

        /*!
         *  \brief Get the size of your gadget
         *  \return the size of the whole gadget
         */
        std::list<Instruction*> get_instructions(void);

        /*!
         *  \brief Get the first offset of this gadget (first offset because a gadget instance stores other offset with the same disassembly in memory)
         *  \return the offset
         */
        unsigned long long get_first_offset(void) const;

        /*!
         *  \brief Get the number of other equivalent gadget
         *  \return the number of the same gadget in memory
         */
        size_t get_nb(void) const;

        /*!
         *  \brief Add the offset where you can find the same gadget
         *
         *  \param offset: the offset where you can find the same gadget
         */
        void add_offset(unsigned long long offset);

        /*!
         *  \brief Get the ending instruction of this gadget
         *  \return a pointer on the ending instruction
         */
        Instruction* Gadget::get_ending_instruction(void);

        static void search_specific_gadget(std::map<std::string, Gadget*> &g);

    private:

        std::string m_disassembly; /*!< the disassembly of the gadget*/

        unsigned int m_size; /*!< the size in byte of the gadget*/

        std::list<Instruction*> m_instructions; /*!< the list of the different instructions composing the gadget*/

        std::vector<unsigned long long> m_offsets; /*!< the vector which stores where you can find the same gadget*/
};

#endif