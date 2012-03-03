#ifndef IA32_H
#define IA32_H

#include "cpu.hpp"
#include "instruction.hpp"

#include <vector>

class Ia32 : public CPU
{
    public:
        explicit Ia32(void);
        ~Ia32(void);

        std::string get_class_name(void) const;
    
    private:
        std::vector<Instruction> m_instructions;
};

#endif