// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "elf_struct.hpp"
#include "executable_format.hpp"
#include "rpexception.hpp"

class Elf : public ExecutableFormat {
public:
  CPU::E_CPU extract_information_from_binary(std::ifstream &file) {
    uint32_t size_init = 0;
    std::array<uint8_t, EI_NIDENT> buf;
    CPU::E_CPU cpu = CPU::CPU_UNKNOWN;
    std::cout << "Loading ELF information.." << std::endl;

    std::streampos off = file.tellg();
    file.seekg(0, std::ios::beg);
    file.read((char *)buf.data(), EI_NIDENT);

    switch (buf.at(EI_CLASS)) {
    case ELFCLASS32: {
      size_init = 4;
      break;
    }

    case ELFCLASS64: {
      size_init = 8;
      break;
    }

    default:
      RAISE_EXCEPTION("Cannot determine the architecture size");
    }

    if (size_init == 8)
      init_properly_ELFLayout<x64Version>();
    else
      init_properly_ELFLayout<x86Version>();

    // Filling the structure now
    m_ELFLayout->fill_structures(file);

    // Set correctly the pointer
    file.seekg(off);

    switch (m_ELFLayout->get_cpu()) {
    case RP_ELFEM_386: {
      cpu = CPU::CPU_x86;
      break;
    }

    case RP_ELFEM_X86_64: {
      cpu = CPU::CPU_x64;
      break;
    }

    case RP_ELFEM_ARM: {
      cpu = CPU::CPU_ARM;
      break;
    }

    default: {
      RAISE_EXCEPTION("Cannot determine the CPU type");
    }
    }

    return cpu;
  }

  std::shared_ptr<CPU> Elf::get_cpu(std::ifstream &file) {
    std::shared_ptr<CPU> cpu;
    CPU::E_CPU cpu_type = extract_information_from_binary(file);

    switch (cpu_type) {
    case CPU::CPU_x86: {
      cpu = std::make_shared<x86>();
      break;
    }

    case CPU::CPU_x64: {
      cpu = std::make_shared<x64>();
      break;
    }

    case CPU::CPU_ARM: {
      cpu = std::make_shared<ARM>();
      break;
    }

    default: {
      RAISE_EXCEPTION("Cannot determine the CPU type");
    }
    }

    if (cpu == nullptr) {
      RAISE_EXCEPTION("Cannot allocate a cpu");
    }

    return cpu;
  }

  void display_information(const VerbosityLevel lvl) const {
    ExecutableFormat::display_information(lvl);
    std::cout << "Elf Information:" << std::endl;
    m_ELFLayout->display(lvl);
  }

  std::string get_class_name() const { return "Elf"; }

  std::vector<std::shared_ptr<Section>>
  get_executables_section(std::ifstream &file) const {
    return m_ELFLayout->get_executable_section(file);
  }

  uint64_t get_image_base_address() const {
    return m_ELFLayout->get_image_base_address();
  }

private:
  CPU::E_CPU extract_information_from_binary(std::ifstream &file) override;

  template <class T> void init_properly_ELFLayout(void) {
    m_ELFLayout = std::make_shared<ELFLayout<T>>();
    if (m_ELFLayout == nullptr)
      RAISE_EXCEPTION("m_ELFLayout allocation failed");
  }

  std::shared_ptr<ExecutableLinkingFormatLayout> m_ELFLayout;
};
