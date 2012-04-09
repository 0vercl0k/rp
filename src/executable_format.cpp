#include "executable_format.hpp"
#include "pe.hpp"
#include "elf.hpp"

ExecutableFormat::ExecutableFormat(void)
{
}

ExecutableFormat::~ExecutableFormat(void)
{	
}

ExecutableFormat* ExecutableFormat::GetExecutableFormat(unsigned int magic_dword)
{
    ExecutableFormat *exe_format = NULL;

    /* Yeah, I told you this was basic. */
    switch(magic_dword)
    {
        case 0x00905A4D:
        {
            exe_format = new (std::nothrow) PE();
            break;
        }

        case 0x464C457F:
        {
            exe_format = new (std::nothrow) Elf();
            break;
        }
    }

    if(exe_format == NULL)
        RAISE_EXCEPTION("Cannot allocate exe_format or cannot determine the executable format used by your file");

    return exe_format;
}