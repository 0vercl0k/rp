#ifndef CPU_H
#define CPU_H

#include <string>
#include <map>

#include "gadget.hpp"

/*! \class CPU
 *
 *  A CPU is an important class that compose a part of the Program class.
 */
class CPU
{
    public:

        explicit CPU(void);
        
        virtual ~CPU(void);

        /*!
         *  \brief Obtain the name of the class (useful when you use the polymorphism)
         *   
         *  \return the name of the class
         */
        virtual std::string get_class_name(void) const = 0;
        

        /*!
         *  \brief Each CPU class is able to find unique gadgets in [p_memory, p_memory+size]
         *   NB: The vaddr field is actually used by the BeaEngine when it disassembles something like jmp instruction, it needs the original virtual address to
         *   give you disassemble correctly (indeed jmp instruction are relative)
         *
         *  \param p_memory: It is a pointer on the memory where you want to find rop gadget
         *  \param size: It is the size of the p_memory
         *  \param vaddr: It is the real virtual address of the memory which will be disassembled (see the previous remark)
         *  \param depth: It is the number of maximum instructions contained by a gadget
         *
         *  \return An association between the disassembly of the gadget and a pointer on a Gadget instance
         */
        virtual std::map<std::string, Gadget*> find_gadget_in_memory(const unsigned char *p_memory, const unsigned long long size, const unsigned long long vaddr, const unsigned int depth) = 0;

        /*! The different architectures RP++ handles */
        enum E_CPU
        {
            CPU_IA32, /*!< Ia32 */
            CPU_IA64, /*!< Ia64 */
            CPU_UNKNOWN /*!< unknown cpu */
        };
};

#endif