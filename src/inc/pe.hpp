#ifndef PE_H
#define PE_H

#include "executable_format.hpp"
#include "pe_struct.hpp"
#include "rpexception.hpp"

class PE : public ExecutableFormat
{
    public:
        explicit PE(void);
        ~PE(void);

        CPU* get_cpu(std::ifstream &file);

        void display_information(const VerbosityLevel lvl) const;

        std::string get_class_name(void) const;

        std::vector<Section*> get_executables_section(std::ifstream & file);

        unsigned long long raw_offset_to_va(const unsigned long long absolute_raw_offset, const unsigned long long absolute_raw_offset_section) const;

    private:
        CPU::E_CPU extract_information_from_binary(std::ifstream &file);
        
        template<class T>
        void init_properly_PELayout()
        {
            m_pPELayout = new (std::nothrow) PELayout<T>;
            if(m_pPELayout == NULL)
                RAISE_EXCEPTION("m_PELayout allocation failed");
        }

        PortableExecutableLayout* m_pPELayout;
        CPU::E_CPU m_CPU;
};

#endif