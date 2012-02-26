#include "executable_format.hpp"

ExecutableFormat::ExecutableFormat(void)
{
}

ExecutableFormat::~ExecutableFormat(void)
{	
}

ExecutableFormat::E_ExecutableFormat ExecutableFormat::FindExecutableFormat(unsigned int magic_dword)
{
    ExecutableFormat::E_ExecutableFormat format = FORMAT_UNKNOWN;

    switch(magic_dword)
    {
        case 0x00905A4D:
        {
            format = FORMAT_PE;
            break;
        }

        case 0x464C457F:
        {
            format = FORMAT_ELF;
            break;
        }
    }

    return format;
}