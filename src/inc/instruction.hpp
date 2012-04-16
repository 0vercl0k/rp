#ifndef INSTRUCTION_HPP
#define INSTRUCTION_HPP

#include <string>

/*! \class Instruction
 *
 *  Each instruction instance holds a disassembly, an offset (where we can find it in memory) and a size
 */
class Instruction
{
    public:
        
        /*!
         *  \brief Build an instruction
         *   
         *  \param disass: The disassembly of the instruction
         *  \param mnemonic: The mnemonic of the instruction
         *  \param offset: A raw offset (relative to a section) where you can find this instruction
         *  \param size: It is the size of the instruction
         */
        explicit Instruction(std::string disass, std::string mnemonic, unsigned long long offset, unsigned int size);
        
        ~Instruction(void);

        /*!
         *  \brief Obtain the absolute address of the instruction thanks to the VA of the section where it was found
         *   
         *  \param disass: The disassembly of the instruction
         *  \param mnemonic: The mnemonic of the instruction
         *  \param offset: A raw offset (relative to a section) where you can find this instruction
         *  \param size: It is the size of the instruction
         *
         *  \return the VA of the instruction
         */
        unsigned long long get_absolute_address(const unsigned char* va_section);

        /*!
         *  \brief Get the size of the instruction
         *
         *  \return the size of the instruction
         */
        unsigned int get_size(void) const;

        /*!
         *  \brief Get the offset of the instruction ; where you can find it
         *
         *  \return the offset of the instruction
         */
        unsigned long long get_offset(void) const;

        /*!
         *  \brief Get the disassembly of the instruction
         *
         *  \return the disassembly of the instruction
         */
        std::string get_disassembly(void) const;

        /*!
         *  \brief Get the mnemonic of the instruction
         *
         *  \return the mnemonic of the instruction
         */
        std::string get_mnemonic(void) const;

    private:

        std::string m_disass; /*!< the disassembly of the instruction */
        
        std::string m_mnemonic; /*!< the mnemonic of the instruction */
        
        unsigned long long m_offset; /*!< the offset of the instruction */
        
        unsigned int m_size; /*!< the size of the instruction */
};

#endif
