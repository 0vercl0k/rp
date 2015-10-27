/*
    This file is part of rp++.

    Copyright (C) 2014, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
    All rights reserved.

    rp++ is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    rp++ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with rp++.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "executable_format.hpp"
#include "pe.hpp"
#include "elf.hpp"
#include "macho.hpp"

std::shared_ptr<ExecutableFormat> ExecutableFormat::GetExecutableFormat(unsigned int magic_dword)
{
    std::shared_ptr<ExecutableFormat> exe_format(nullptr);
    if((magic_dword & 0xffff) == 0x5A4D)
        exe_format = std::make_shared<PE>();
    else
    {
        /* Yeah, I told you it was basic. */
        switch(magic_dword)
        {
            case 0x464C457F:
            {
                exe_format = std::make_shared<Elf>();
                break;
            }
        
            /* this is for x64 */
            case 0xFEEDFACF:
            /* this one for x86 */
            case 0xFEEDFACE:
            {
                exe_format = std::make_shared<Macho>();
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
    }

    if(exe_format == nullptr)
        RAISE_EXCEPTION("Cannot allocate exe_format");

    return exe_format;
}
