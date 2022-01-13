// Axel '0vercl0k' Souchet - January 12 2022
#include "executable_format.hpp"
#include "elf.hpp"
#include "macho.hpp"
#include "pe.hpp"

std::shared_ptr<ExecutableFormat>
ExecutableFormat::GetExecutableFormat(uint32_t magic_dword) {
  std::shared_ptr<ExecutableFormat> exe_format(nullptr);
  if ((magic_dword & 0xffff) == 0x5A4D)
    exe_format = std::make_shared<PE>();
  else {
    /* Yeah, I told you it was basic. */
    switch (magic_dword) {
    case 0x464C457F: {
      exe_format = std::make_shared<Elf>();
      break;
    }

    /* this is for x64 */
    case 0xFEEDFACF:
    /* this one for x86 */
    case 0xFEEDFACE: {
      exe_format = std::make_shared<Macho>();
      break;
    }

    case 0xBEBAFECA: {
      RAISE_EXCEPTION("Hmm, actually I don't handle OSX Universal binaries. "
                      "You must extract them manually.");
      break;
    }

    default:
      RAISE_EXCEPTION("Cannot determine the executable format used");
    }
  }

  if (exe_format == nullptr)
    RAISE_EXCEPTION("Cannot allocate exe_format");

  return exe_format;
}
