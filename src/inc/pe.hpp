#ifndef PE_H
#define PE_H

#include "executable_format.hpp"
#include "pe_struct.hpp"

class PE : public ExecutableFormat
{
    public:
        explicit PE(void);
        ~PE(void);

        CPU* get_cpu(std::ifstream &file);

        void display_information(VerbosityLevel lvl);

        std::string get_class_name(void) const;

        std::vector<Section*> get_executables_section(void);

    private:
        CPU::E_CPU extract_information_from_binary(std::ifstream &file);
        
        template<class T>
        void init_properly_PELayout()
        {
            m_pPELayout = new PELayout<T>;
            if(m_pPELayout == NULL)
                throw std::string("m_PELayout allocation failed");
        }

        PortableExecutableLayout* m_pPELayout;
        CPU::E_CPU m_CPU;
};

#endif