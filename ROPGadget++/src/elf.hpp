#ifndef ELF_H
#define ELF_H

#include "executable_format.hpp"
#include "elf_struct.h"

class Elf : public ExecutableFormat
{
    public:
        explicit Elf(void);
        ~Elf(void);

        std::string get_class(void);
        CPU* get_cpu(std::ifstream &file);
        void display_information(VerbosityLevel lvl);

    private:
        CPU::E_CPU load_elf_information(std::ifstream &file);

        template<class T>
        void init_properly_ELFLayout(void)
        {
            m_ELFLayout = new ELFLayout<T>;
            if(m_ELFLayout == NULL)
                throw std::string("m_ELFLayout allocation failed");
        }

        ExecutableLinkingFormatLayout* m_ELFLayout;
        CPU::E_CPU m_CPU;
};

#endif