#ifndef CPU_H
#define CPU_H

#include <string>

class CPU
{
    public:
        explicit CPU(void);
        ~CPU(void);

        virtual std::string get_class_name(void) const = 0;

        enum E_CPU
        {
            CPU_IA32,
            CPU_IA64,
            CPU_UNKNOWN
        };
};

#endif