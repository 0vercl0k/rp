#ifndef ELF_H
#define ELF_H

#include "executable_format.hpp"
#include "elf_struct.hpp"

class Elf : public ExecutableFormat
{
    public:
        explicit Elf(void);
        ~Elf(void);

        CPU* get_cpu(std::ifstream &file);

        void display_information(const VerbosityLevel lvl) const;

        std::string get_class_name(void) const;

        std::vector<Section*> get_executables_section(std::ifstream & file);

        unsigned long long raw_offset_to_va(const unsigned long long absolute_raw_offset, const unsigned long long absolute_raw_offset_section) const;

    private:

        CPU::E_CPU extract_information_from_binary(std::ifstream &file);

        template<class T>
        void init_properly_ELFLayout(void)
        {
            m_ELFLayout = new (std::nothrow) ELFLayout<T>;
            if(m_ELFLayout == NULL)
                throw std::string("m_ELFLayout allocation failed");
        }

        ExecutableLinkingFormatLayout* m_ELFLayout;
        CPU::E_CPU m_CPU;
};

#endif