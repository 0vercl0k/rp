#ifndef IA32_H
#define IA32_H

#include "cpu.hpp"

class Ia32 : public CPU
{
    public:
        explicit Ia32(void);
        ~Ia32(void);

        std::string get_class_name(void) const;
};

#endif