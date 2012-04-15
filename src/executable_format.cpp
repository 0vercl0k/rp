#include "executable_format.hpp"
#include "pe.hpp"
#include "elf.hpp"
#include "macho.hpp"

ExecutableFormat::ExecutableFormat(void)
{
}

ExecutableFormat::~ExecutableFormat(void)
{	
}

ExecutableFormat* ExecutableFormat::GetExecutableFormat(unsigned int magic_dword)
{
    ExecutableFormat *exe_format = NULL;

    /* Yeah, I told you it was basic. */
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
        
        /* this is for x64 */
        case 0xFEEDFACF:
        /* this one for x86 */
        case 0xFEEDFACE:
        {
            exe_format = new (std::nothrow) Macho();
            break;
        }

        case 0xBEBAFECA:
        {
            RAISE_EXCEPTION("Hmm, actually I don't handle OSX Universal binaries. You must extract them manually.");
            break;
        }

        default:
            RAISE_EXCEPTION("Cannot determine the executable format used");
    }

    if(exe_format == NULL)
        RAISE_EXCEPTION("Cannot allocate exe_format");

    return exe_format;
}