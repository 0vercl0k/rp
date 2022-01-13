// Axel '0vercl0k' Souchet - January 12 2022
#include "macho.hpp"
#include "x64.hpp"
#include "x86.hpp"

std::shared_ptr<CPU> Macho::get_cpu(std::ifstream &file) {
  std::shared_ptr<CPU> cpu(nullptr);
  RP_MACH_HEADER<x86Version> header32;

  std::cout << "Loading Mach-O information.." << std::endl;

  /* Remember where the caller was in the file */
  std::streampos off = file.tellg();

  file.seekg(0, std::ios::beg);
  file.read((char *)&header32, sizeof(RP_MACH_HEADER<x86Version>));

  switch (header32.cputype) {
  case CPU_TYPE_x86_64: {
    cpu = std::make_shared<x64>();
    init_properly_macho_layout<x64Version>();
    break;
  }

  case CPU_TYPE_I386: {
    cpu = std::make_shared<x86>();
    init_properly_macho_layout<x86Version>();
    break;
  }

  default:
    RAISE_EXCEPTION(
        "Cannot determine which architecture is used in this Mach-O file");
  }

  file.seekg(off);

  if (cpu == nullptr)
    RAISE_EXCEPTION("Cannot allocate cpu");

  /* Now we can fill the structure */
  m_MachoLayout->fill_structures(file);

  return cpu;
}

std::string Macho::get_class_name(void) const { return "Mach-o"; }

std::vector<std::shared_ptr<Section>>
Macho::get_executables_section(std::ifstream &file) const {
  return m_MachoLayout->get_executable_section(file);
}

uint64_t
Macho::raw_offset_to_va(const uint64_t absolute_raw_offset,
                        const uint64_t absolute_raw_offset_section) const {
  return 0ULL;
}

CPU::E_CPU Macho::extract_information_from_binary(std::ifstream &file) {
  return CPU::CPU_UNKNOWN;
}

void Macho::display_information(const VerbosityLevel lvl) const {
  ExecutableFormat::display_information(lvl);
  m_MachoLayout->display(lvl);
}

uint64_t Macho::get_image_base_address(void) const {
  return m_MachoLayout->get_image_base_address();
}